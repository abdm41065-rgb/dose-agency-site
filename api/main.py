"""Silver Charm API: the only thing that talks to the database (as role sc_api, functions only).
Env: DATABASE_URL (sc_api login), TG_BOT_TOKEN, TG_CHAT_ID, ALLOWED_ORIGINS (comma list), TG_DRY_RUN=1 for tests."""
import asyncio, json, os, logging, urllib.request, urllib.parse, uuid
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, UploadFile, Form, File
from fastapi.responses import JSONResponse
from psycopg_pool import AsyncConnectionPool
import psycopg

log = logging.getLogger('sc')
DB = os.environ['DATABASE_URL']
TG_TOKEN = os.environ.get('TG_BOT_TOKEN', '')
TG_CHAT = os.environ.get('TG_CHAT_ID', '')
TG_DRY = os.environ.get('TG_DRY_RUN') == '1'
ORIGINS = {o.strip() for o in os.environ.get('ALLOWED_ORIGINS', '').split(',') if o.strip()}
MAX_PHOTO = 5_000_000
pool = AsyncConnectionPool(DB, min_size=1, max_size=5, open=False, kwargs={'autocommit': True})

# user-facing messages for DB error codes (raised by api.* functions)
ERR = {'BAD_PHONE': 'اكتب رقم عراقي صحيح يبدي بـ07.', 'BAD_GOV': 'اختار المحافظة.', 'BAD_PRODUCT': 'هاي القطعة مو متوفرة حالياً.',
       'BAD_ID': 'اكتب رقم هويتك بشكل صحيح.', 'NO_PHOTO': 'ارفع صورة هويتك.', 'RATE_LIMIT': 'طلبات كثيرة، جرّب بعد شوية.'}

def client_ip(req: Request) -> str:
    for h in ('do-connecting-ip', 'cf-connecting-ip'):
        if req.headers.get(h): return req.headers[h].strip()
    xff = req.headers.get('x-forwarded-for')
    return xff.split(',')[0].strip() if xff else (req.client.host if req.client else '0.0.0.0')

def db_error(e: psycopg.Error):
    msg = (e.diag.message_primary or '') if e.diag else ''
    if msg in ERR: return JSONResponse({'ok': False, 'error': msg, 'message': ERR[msg]}, 429 if msg == 'RATE_LIMIT' else 400)
    if isinstance(e, (psycopg.errors.CheckViolation, psycopg.errors.NotNullViolation, psycopg.errors.StringDataRightTruncation)):
        return JSONResponse({'ok': False, 'error': 'INVALID', 'message': 'تأكد من المعلومات اللي كتبتها.'}, 400)
    log.exception('db error')
    return JSONResponse({'ok': False, 'error': 'SERVER', 'message': 'صار خلل، حاول مرة ثانية.'}, 500)

def sniff_image(b: bytes):
    if b[:3] == b'\xff\xd8\xff': return 'image/jpeg'
    if b[:8] == b'\x89PNG\r\n\x1a\n': return 'image/png'
    if b[:4] == b'RIFF' and b[8:12] == b'WEBP': return 'image/webp'
    if b[4:8] == b'ftyp' and b[8:12] in (b'heic', b'heix', b'mif1', b'msf1'): return 'image/heic'
    return None

# ── Telegram worker: drains app.telegram_outbox (retries handled by the DB) ──
def tg_call(method, fields=None, files=None):
    if TG_DRY or not TG_TOKEN:
        log.info('TG dry-run %s %s', method, fields); return True
    url = f'https://api.telegram.org/bot{TG_TOKEN}/{method}'
    if files:
        bnd = uuid.uuid4().hex; body = b''
        for k, v in (fields or {}).items():
            body += f'--{bnd}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode()
        for k, (fn, data, mime) in files.items():
            body += f'--{bnd}\r\nContent-Disposition: form-data; name="{k}"; filename="{fn}"\r\nContent-Type: {mime}\r\n\r\n'.encode() + data + b'\r\n'
        body += f'--{bnd}--\r\n'.encode()
        rq = urllib.request.Request(url, data=body, headers={'Content-Type': f'multipart/form-data; boundary={bnd}'})
    else:
        rq = urllib.request.Request(url, data=urllib.parse.urlencode(fields).encode())
    with urllib.request.urlopen(rq, timeout=20) as r:
        return json.load(r).get('ok', False)

def fmt(kind, p):
    if kind == 'order':
        return (f"🛍 طلب جديد #{p['order_no']}\nالقطعة: {p['product']}\nالاسم: {p['name']}\nالرقم: {p['phone']}\n"
                f"المحافظة: {p['gov']}\nالعنوان: {p['address']}" + (f"\nملاحظة: {p['note']}" if p.get('note') else ''))
    return (f"♥ مرة وحدة بالعمر · شهادة N° {int(p['cert_no']):04d}\n{p['him']} ♥ {p['her']}\nالقطعة: {p['product']}\n"
            f"الرقم: {p['phone']}\nصورة الهوية مرفقة للتحقق، وتنمسح تلقائياً بعد 30 يوم.")

async def tg_worker():
    while True:
        try:
            async with pool.connection() as c:
                rows = await (await c.execute('SELECT id, kind, payload FROM api.outbox_claim(10)')).fetchall()
                for mid, kind, payload in rows:
                    text = fmt(kind, payload)
                    if kind == 'once':
                        ph = await (await c.execute('SELECT mime, data FROM api.id_photo(%s)', (payload['cert_no'],))).fetchone()
                        ok = await asyncio.to_thread(tg_call, 'sendPhoto', {'chat_id': TG_CHAT, 'caption': text},
                                                     {'photo': ('id.jpg', bytes(ph[1]), ph[0])}) if ph else await asyncio.to_thread(tg_call, 'sendMessage', {'chat_id': TG_CHAT, 'text': text})
                    else:
                        ok = await asyncio.to_thread(tg_call, 'sendMessage', {'chat_id': TG_CHAT, 'text': text})
                    if ok: await c.execute('SELECT api.outbox_done(%s)', (mid,))
        except Exception:
            log.exception('tg worker')
        await asyncio.sleep(4)

async def purge_worker():
    while True:
        try:
            async with pool.connection() as c:
                await c.execute('SELECT api.purge_id_photos(30)')
        except Exception:
            log.exception('purge')
        await asyncio.sleep(6 * 3600)

@asynccontextmanager
async def lifespan(app):
    await pool.open()
    tasks = [asyncio.create_task(tg_worker()), asyncio.create_task(purge_worker())]
    yield
    for t in tasks: t.cancel()
    await pool.close()

app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

@app.middleware('http')
async def guard(request: Request, call_next):
    if request.method == 'POST':
        origin = request.headers.get('origin', '')
        if ORIGINS and origin not in ORIGINS:  # blocks other sites from posting orders on a visitor's behalf
            return JSONResponse({'ok': False, 'error': 'ORIGIN'}, 403)
        if int(request.headers.get('content-length') or 0) > MAX_PHOTO + 200_000:
            return JSONResponse({'ok': False, 'error': 'TOO_LARGE', 'message': 'الصورة كبيرة، اختار صورة أصغر.'}, 413)
    resp = await call_next(request)
    resp.headers.update({'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer',
                         'X-Frame-Options': 'DENY', 'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'})
    return resp

@app.get('/api/health')
async def health():
    async with pool.connection() as c:
        await c.execute('SELECT 1')
    return {'ok': True}

@app.get('/api/products')
async def products():
    async with pool.connection() as c:
        rows = await (await c.execute('SELECT slug,type,name_ar,name_en,description,specs,weight_g,price_iqd,images FROM api.list_products()')).fetchall()
    return [{'id': r[0], 'type': r[1], 'ar': r[2], 'en': r[3], 'desc': r[4], 'list': r[5], 'weight_g': float(r[6]) if r[6] is not None else None,
             'price_iqd': r[7], 'imgs': r[8]} for r in rows]

@app.post('/api/order')
async def order(request: Request):
    try:
        b = await request.json()
        f = {k: str(b.get(k) or '')[:300] for k in ('name', 'phone', 'gov', 'addr', 'note', 'piece')}
    except Exception:
        return JSONResponse({'ok': False, 'error': 'INVALID'}, 400)
    try:
        async with pool.connection() as c:
            no = (await (await c.execute('SELECT api.place_order(%s,%s,%s,%s,%s,%s,%s)',
                  (f['name'], f['phone'], f['gov'], f['addr'], f['note'], f['piece'], client_ip(request)))).fetchone())[0]
        return {'ok': True, 'order_no': no}
    except psycopg.Error as e:
        return db_error(e)

@app.post('/api/once')
async def once(request: Request, him: str = Form(..., max_length=24), her: str = Form(..., max_length=24), phone: str = Form(..., max_length=20),
               email: str = Form('', max_length=80), id_number: str = Form(..., max_length=30), piece: str = Form(..., max_length=40),
               photo: UploadFile = File(...)):
    data = await photo.read(MAX_PHOTO + 1)
    if len(data) > MAX_PHOTO: return JSONResponse({'ok': False, 'error': 'TOO_LARGE', 'message': 'الصورة كبيرة، اختار صورة أصغر.'}, 413)
    mime = sniff_image(data)  # trust the bytes, not the filename or browser-sent type
    if not mime: return JSONResponse({'ok': False, 'error': 'BAD_PHOTO', 'message': 'لازم تكون صورة (JPG أو PNG).'}, 400)
    try:
        async with pool.connection() as c:
            r = (await (await c.execute('SELECT api.place_once(%s,%s,%s,%s,%s,%s,%s,%s,%s)',
                 (him, her, phone, email, id_number, data, mime, piece, client_ip(request)))).fetchone())[0]
        return {'ok': True, **r}
    except psycopg.Error as e:
        return db_error(e)
