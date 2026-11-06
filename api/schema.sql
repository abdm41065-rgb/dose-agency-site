-- Silver Charm database (PostgreSQL 15+). Self-hosted; the website never connects directly:
-- only the backend API logs in (role sc_api) and it can ONLY call functions in schema "api".
-- Layers inside the DB: roles + revoked defaults, schemas split, SECURITY DEFINER entry points,
-- row level security (forced), CHECK/UNIQUE constraints, hashed identifiers, rate limits, audit log, outbox.

BEGIN;

-- no extensions needed: built-in sha256() and gen_random_uuid() (PostgreSQL 13+)

-- ───────────────────────── roles ─────────────────────────
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='sc_owner') THEN CREATE ROLE sc_owner NOLOGIN; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='sc_api')   THEN CREATE ROLE sc_api   NOLOGIN; END IF; -- backend (LOGIN + password set at deploy)
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='sc_admin') THEN CREATE ROLE sc_admin NOLOGIN; END IF; -- owner dashboard
END $$;
-- the migrating admin (superuser or DO 'doadmin') must be able to SET ROLE sc_owner
DO $$ BEGIN EXECUTE format('GRANT sc_owner TO %I', current_user); END $$;

REVOKE ALL ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA IF NOT EXISTS app   AUTHORIZATION sc_owner;  -- tables (no direct access for api/admin)
CREATE SCHEMA IF NOT EXISTS audit AUTHORIZATION sc_owner;  -- append-only history
CREATE SCHEMA IF NOT EXISTS api   AUTHORIZATION sc_owner;  -- the only callable surface
REVOKE ALL ON SCHEMA app, audit, api FROM PUBLIC;
GRANT USAGE ON SCHEMA api TO sc_api, sc_admin;

SET ROLE sc_owner;

-- ───────────────────────── reference data ─────────────────────────
CREATE TYPE app.product_type AS ENUM ('bracelet','ring','necklace','earring');
CREATE TYPE app.order_status AS ENUM ('pending','confirmed','preparing','shipped','delivered','cancelled');

CREATE TABLE app.governorates (
  code  text PRIMARY KEY,
  name_ar text NOT NULL UNIQUE
);
INSERT INTO app.governorates(code,name_ar) VALUES
 ('BGD','بغداد'),('BSR','البصرة'),('NIN','نينوى'),('ERB','أربيل'),('SUL','السليمانية'),('DUH','دهوك'),
 ('KIR','كركوك'),('NAJ','النجف'),('KAR','كربلاء'),('BAB','بابل'),('DIY','ديالى'),('ANB','الأنبار'),
 ('SAL','صلاح الدين'),('WAS','واسط'),('QAD','القادسية'),('MUT','المثنى'),('DHQ','ذي قار'),('MAY','ميسان'),('HAL','حلبجة');

-- ───────────────────────── catalogue ─────────────────────────
CREATE TABLE app.products (
  id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  slug        text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9-]{2,40}$'),
  type        app.product_type NOT NULL,
  name_ar     text NOT NULL CHECK (length(name_ar) BETWEEN 2 AND 80),
  name_en     text NOT NULL CHECK (length(name_en) BETWEEN 2 AND 80),
  description text NOT NULL DEFAULT '' CHECK (length(description) <= 600),
  specs       text[] NOT NULL DEFAULT '{}',
  weight_g    numeric(6,2) CHECK (weight_g > 0 AND weight_g < 1000),
  price_iqd   integer CHECK (price_iqd >= 0),
  images      text[] NOT NULL DEFAULT '{}' CHECK (cardinality(images) <= 8),
  hallmark    text NOT NULL DEFAULT '925',
  is_active   boolean NOT NULL DEFAULT true,
  sort        integer NOT NULL DEFAULT 0,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);

-- ───────────────────────── customers ─────────────────────────
-- phone is kept (needed to call for delivery); phone_hash is an HMAC with a server pepper so
-- uniqueness checks never depend on how the number was typed (+964 / 07 / Arabic digits are normalized by api.norm_phone).
CREATE TABLE app.customers (
  id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  name        text NOT NULL CHECK (length(btrim(name)) BETWEEN 2 AND 40),
  phone       text NOT NULL UNIQUE CHECK (phone ~ '^07[0-9]{9}$'),
  email       text CHECK (email IS NULL OR email ~* '^[^@\s]+@[^@\s]+\.[^@\s]{2,}$'),
  created_at  timestamptz NOT NULL DEFAULT now()
);

-- ───────────────────────── normal orders ─────────────────────────
CREATE TABLE app.orders (
  id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  order_no    bigint GENERATED ALWAYS AS IDENTITY (START WITH 1001) UNIQUE,
  customer_id bigint NOT NULL REFERENCES app.customers(id) ON DELETE RESTRICT,
  product_id  bigint NOT NULL REFERENCES app.products(id)  ON DELETE RESTRICT,
  governorate text   NOT NULL REFERENCES app.governorates(code),
  address     text   NOT NULL CHECK (length(btrim(address)) BETWEEN 4 AND 120),
  note        text   NOT NULL DEFAULT '' CHECK (length(note) <= 300),
  price_iqd   integer CHECK (price_iqd >= 0),               -- snapshot at order time
  status      app.order_status NOT NULL DEFAULT 'pending',
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX orders_status_idx ON app.orders(status, created_at DESC);

-- ───────────────────────── once in a lifetime ─────────────────────────
-- The lifetime lock lives HERE, not in the browser: one row per phone and one per national ID, forever.
-- No engraving: names are printed on the certificate only. The ID photo itself sits in private object
-- storage (key only stored here) and is purged after verification; only HMACs of identifiers remain.
CREATE SEQUENCE app.once_cert_seq START 1;
CREATE TABLE app.once_orders (
  id             bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  cert_no        integer NOT NULL UNIQUE DEFAULT nextval('app.once_cert_seq'),
  customer_id    bigint  NOT NULL UNIQUE REFERENCES app.customers(id) ON DELETE RESTRICT,
  phone_hash     bytea   NOT NULL UNIQUE,
  id_number_hash bytea   NOT NULL UNIQUE,
  him_name       text    NOT NULL CHECK (length(btrim(him_name)) BETWEEN 2 AND 24),
  her_name       text    NOT NULL CHECK (length(btrim(her_name)) BETWEEN 2 AND 24),
  product_id     bigint  NOT NULL REFERENCES app.products(id) ON DELETE RESTRICT,
  id_verified_at timestamptz,
  id_purged_at   timestamptz,
  status         app.order_status NOT NULL DEFAULT 'pending',
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now()
);
-- ID photo kept only until verification (purged after 30 days); separate table so it never appears in audit/outbox rows
CREATE TABLE app.id_photos (
  once_id    bigint PRIMARY KEY REFERENCES app.once_orders(id) ON DELETE CASCADE,
  mime       text   NOT NULL CHECK (mime IN ('image/jpeg','image/png','image/webp','image/heic')),
  data       bytea  NOT NULL CHECK (octet_length(data) BETWEEN 1000 AND 5000000),
  created_at timestamptz NOT NULL DEFAULT now()
);
ALTER SEQUENCE app.once_cert_seq OWNED BY app.once_orders.cert_no;

-- ───────────────────────── rate limits + outbox ─────────────────────────
CREATE TABLE app.rate_hits (
  bucket text NOT NULL,           -- e.g. 'order:ip:1.2.3.4' or 'once:phone:<hash>'
  at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX rate_hits_idx ON app.rate_hits(bucket, at DESC);

CREATE TABLE app.telegram_outbox (
  id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  kind       text NOT NULL CHECK (kind IN ('order','once','alert')),
  ref_no     bigint NOT NULL,
  payload    jsonb  NOT NULL,
  attempts   smallint NOT NULL DEFAULT 0,
  locked_at  timestamptz,
  sent_at    timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX outbox_pending_idx ON app.telegram_outbox(created_at) WHERE sent_at IS NULL;

-- ───────────────────────── secrets (pepper) ─────────────────────────
-- Single-row table readable only by sc_owner (the SECURITY DEFINER functions). Set the real value at deploy.
CREATE TABLE app.secrets (
  id     boolean PRIMARY KEY DEFAULT true CHECK (id),
  pepper bytea NOT NULL
);
INSERT INTO app.secrets(pepper) VALUES (decode(replace(gen_random_uuid()::text||gen_random_uuid()::text,'-',''),'hex'));  -- 32 random bytes

-- ───────────────────────── audit (append-only) ─────────────────────────
CREATE TABLE audit.log (
  id      bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  at      timestamptz NOT NULL DEFAULT now(),
  actor   text NOT NULL,
  tbl     text NOT NULL,
  op      text NOT NULL,
  row_id  bigint,
  old     jsonb,
  new     jsonb
);

CREATE FUNCTION audit.capture() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  INSERT INTO audit.log(actor,tbl,op,row_id,old,new)
  VALUES (coalesce(nullif(current_setting('app.actor',true),''),session_user::text), TG_TABLE_NAME, TG_OP,
          coalesce((to_jsonb(NEW)->>'id')::bigint,(to_jsonb(OLD)->>'id')::bigint),
          CASE WHEN TG_OP<>'INSERT' THEN to_jsonb(OLD) - 'phone_hash' - 'id_number_hash' END,
          CASE WHEN TG_OP<>'DELETE' THEN to_jsonb(NEW) - 'phone_hash' - 'id_number_hash' END);
  RETURN coalesce(NEW,OLD);
END $$;

CREATE FUNCTION app.touch() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN NEW.updated_at := now(); RETURN NEW; END $$;

-- audit log can never be edited or deleted
CREATE FUNCTION audit.block_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'audit log is append-only'; END $$;
CREATE TRIGGER audit_log_immutable BEFORE UPDATE OR DELETE ON audit.log FOR EACH ROW EXECUTE FUNCTION audit.block_change();

-- once orders can never be deleted (the lock is permanent)
CREATE FUNCTION app.block_delete() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'once-in-a-lifetime orders cannot be deleted'; END $$;
CREATE TRIGGER once_no_delete BEFORE DELETE ON app.once_orders FOR EACH ROW EXECUTE FUNCTION app.block_delete();

CREATE TRIGGER products_touch BEFORE UPDATE ON app.products    FOR EACH ROW EXECUTE FUNCTION app.touch();
CREATE TRIGGER orders_touch   BEFORE UPDATE ON app.orders      FOR EACH ROW EXECUTE FUNCTION app.touch();
CREATE TRIGGER once_touch     BEFORE UPDATE ON app.once_orders FOR EACH ROW EXECUTE FUNCTION app.touch();
CREATE TRIGGER products_audit AFTER INSERT OR UPDATE OR DELETE ON app.products    FOR EACH ROW EXECUTE FUNCTION audit.capture();
CREATE TRIGGER orders_audit   AFTER INSERT OR UPDATE OR DELETE ON app.orders      FOR EACH ROW EXECUTE FUNCTION audit.capture();
CREATE TRIGGER once_audit     AFTER INSERT OR UPDATE OR DELETE ON app.once_orders FOR EACH ROW EXECUTE FUNCTION audit.capture();
CREATE TRIGGER customers_audit AFTER INSERT OR UPDATE OR DELETE ON app.customers  FOR EACH ROW EXECUTE FUNCTION audit.capture();

-- ───────────────────────── row level security (defense in depth) ─────────────────────────
-- api/admin roles have no table grants at all; RLS is forced so even a mistaken GRANT exposes nothing.
ALTER TABLE app.products        ENABLE ROW LEVEL SECURITY; ALTER TABLE app.products        FORCE ROW LEVEL SECURITY;
ALTER TABLE app.customers       ENABLE ROW LEVEL SECURITY; ALTER TABLE app.customers       FORCE ROW LEVEL SECURITY;
ALTER TABLE app.orders          ENABLE ROW LEVEL SECURITY; ALTER TABLE app.orders          FORCE ROW LEVEL SECURITY;
ALTER TABLE app.once_orders     ENABLE ROW LEVEL SECURITY; ALTER TABLE app.once_orders     FORCE ROW LEVEL SECURITY;
ALTER TABLE app.telegram_outbox ENABLE ROW LEVEL SECURITY; ALTER TABLE app.telegram_outbox FORCE ROW LEVEL SECURITY;
ALTER TABLE app.rate_hits       ENABLE ROW LEVEL SECURITY; ALTER TABLE app.rate_hits       FORCE ROW LEVEL SECURITY;
ALTER TABLE app.secrets         ENABLE ROW LEVEL SECURITY; ALTER TABLE app.secrets         FORCE ROW LEVEL SECURITY;
ALTER TABLE app.id_photos       ENABLE ROW LEVEL SECURITY; ALTER TABLE app.id_photos       FORCE ROW LEVEL SECURITY;
ALTER TABLE app.governorates    ENABLE ROW LEVEL SECURITY; ALTER TABLE app.governorates    FORCE ROW LEVEL SECURITY;
-- only the owner (used by SECURITY DEFINER functions) sees rows
CREATE POLICY owner_all ON app.products        TO sc_owner USING (true) WITH CHECK (true);
CREATE POLICY owner_all ON app.customers       TO sc_owner USING (true) WITH CHECK (true);
CREATE POLICY owner_all ON app.orders          TO sc_owner USING (true) WITH CHECK (true);
CREATE POLICY owner_all ON app.once_orders     TO sc_owner USING (true) WITH CHECK (true);
CREATE POLICY owner_all ON app.telegram_outbox TO sc_owner USING (true) WITH CHECK (true);
CREATE POLICY owner_all ON app.rate_hits       TO sc_owner USING (true) WITH CHECK (true);
CREATE POLICY owner_all ON app.secrets         TO sc_owner USING (true) WITH CHECK (true);
CREATE POLICY owner_all ON app.governorates    TO sc_owner USING (true) WITH CHECK (true);
CREATE POLICY owner_all ON app.id_photos       TO sc_owner USING (true) WITH CHECK (true);

-- ───────────────────────── helpers ─────────────────────────
-- normalize Iraqi mobile: Arabic/Persian digits, spaces, +964 / 00964 / 964 prefixes → 07XXXXXXXXX
CREATE FUNCTION api.norm_phone(p text) RETURNS text LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT CASE
    WHEN d ~ '^07[0-9]{9}$' THEN d
    WHEN d ~ '^9647[0-9]{9}$' THEN '0'||substr(d,4)
    WHEN d ~ '^009647[0-9]{9}$' THEN '0'||substr(d,6)
    WHEN d ~ '^7[0-9]{9}$' THEN '0'||d
  END
  FROM (SELECT regexp_replace(translate(coalesce(p,''),'٠١٢٣٤٥٦٧٨٩۰۱۲۳۴۵۶۷۸۹','01234567890123456789'),'[^0-9]','','g') AS d) s
$$;

CREATE FUNCTION app.hmac_of(v text) RETURNS bytea LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  -- keyed hash: sha256(secret pepper || value). Only equality is ever checked, so length-extension is irrelevant.
  SELECT sha256((SELECT pepper FROM app.secrets) || convert_to(v,'UTF8'))
$$;

-- returns true when allowed; records the hit. limit per window.
CREATE FUNCTION app.rate_ok(b text, max_hits int, win interval) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE n int;
BEGIN
  DELETE FROM app.rate_hits WHERE at < now() - interval '2 days';
  SELECT count(*) INTO n FROM app.rate_hits WHERE bucket=b AND at > now()-win;
  IF n >= max_hits THEN RETURN false; END IF;
  INSERT INTO app.rate_hits(bucket) VALUES (b);
  RETURN true;
END $$;

-- ───────────────────────── public API (the only door) ─────────────────────────
CREATE FUNCTION api.list_products() RETURNS TABLE(slug text,type text,name_ar text,name_en text,description text,specs text[],weight_g numeric,price_iqd int,images text[])
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT p.slug,p.type::text,p.name_ar,p.name_en,p.description,p.specs,p.weight_g,p.price_iqd,p.images
  FROM app.products p WHERE p.is_active ORDER BY p.sort, p.id
$$;

CREATE FUNCTION api.place_order(p_name text,p_phone text,p_gov text,p_address text,p_note text,p_product text,p_ip inet)
RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE ph text := api.norm_phone(p_phone); cid bigint; pr app.products; no bigint; gc text;
BEGIN
  IF ph IS NULL THEN RAISE EXCEPTION 'BAD_PHONE' USING ERRCODE='22023'; END IF;
  IF NOT app.rate_ok('order:ip:'||host(p_ip),10,'1 hour') OR NOT app.rate_ok('order:phone:'||ph,3,'1 hour') THEN
    RAISE EXCEPTION 'RATE_LIMIT' USING ERRCODE='P0429'; END IF;
  SELECT code INTO gc FROM app.governorates WHERE code=p_gov OR name_ar=btrim(p_gov);
  IF gc IS NULL THEN RAISE EXCEPTION 'BAD_GOV' USING ERRCODE='22023'; END IF;
  SELECT * INTO pr FROM app.products WHERE slug=p_product AND is_active;
  IF NOT FOUND THEN RAISE EXCEPTION 'BAD_PRODUCT' USING ERRCODE='22023'; END IF;
  INSERT INTO app.customers(name,phone) VALUES (btrim(p_name),ph)
    ON CONFLICT (phone) DO UPDATE SET name=EXCLUDED.name RETURNING id INTO cid;
  INSERT INTO app.orders(customer_id,product_id,governorate,address,note,price_iqd)
    VALUES (cid,pr.id,gc,btrim(p_address),coalesce(btrim(p_note),''),pr.price_iqd) RETURNING order_no INTO no;
  INSERT INTO app.telegram_outbox(kind,ref_no,payload) VALUES ('order',no,
    jsonb_build_object('order_no',no,'name',btrim(p_name),'phone',ph,'gov',(SELECT name_ar FROM app.governorates WHERE code=gc),'address',btrim(p_address),'note',coalesce(p_note,''),'product',pr.name_ar));
  RETURN no;
END $$;

-- returns {"status":"ok","cert_no":n} or {"status":"used","cert_no":old}. "used" is a normal return (not an error)
-- so the rate-limit hit is committed: nobody can probe phone/ID numbers without being throttled.
CREATE FUNCTION api.place_once(p_him text,p_her text,p_phone text,p_email text,p_id_number text,p_photo bytea,p_photo_mime text,p_product text,p_ip inet)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE ph text := api.norm_phone(p_phone); idn text := regexp_replace(upper(coalesce(p_id_number,'')),'[^0-9A-Z]','','g');
        hp bytea; hi bytea; cid bigint; pr app.products; cert int; prev int; oid bigint;
BEGIN
  IF ph IS NULL THEN RAISE EXCEPTION 'BAD_PHONE' USING ERRCODE='22023'; END IF;
  IF length(idn) < 6 THEN RAISE EXCEPTION 'BAD_ID' USING ERRCODE='22023'; END IF;
  IF p_photo IS NULL THEN RAISE EXCEPTION 'NO_PHOTO' USING ERRCODE='22023'; END IF;
  IF NOT app.rate_ok('once:ip:'||host(p_ip),5,'1 hour') THEN RAISE EXCEPTION 'RATE_LIMIT' USING ERRCODE='P0429'; END IF;
  hp := app.hmac_of('phone:'||ph); hi := app.hmac_of('id:'||idn);
  SELECT cert_no INTO prev FROM app.once_orders WHERE phone_hash=hp OR id_number_hash=hi LIMIT 1;
  IF FOUND THEN RETURN jsonb_build_object('status','used','cert_no',prev); END IF;
  SELECT * INTO pr FROM app.products WHERE slug=p_product AND is_active;
  IF NOT FOUND THEN RAISE EXCEPTION 'BAD_PRODUCT' USING ERRCODE='22023'; END IF;
  INSERT INTO app.customers(name,phone,email) VALUES (btrim(p_him),ph,nullif(btrim(p_email),''))
    ON CONFLICT (phone) DO UPDATE SET email=coalesce(EXCLUDED.email,app.customers.email) RETURNING id INTO cid;
  BEGIN
    INSERT INTO app.once_orders(customer_id,phone_hash,id_number_hash,him_name,her_name,product_id)
      VALUES (cid,hp,hi,btrim(p_him),btrim(p_her),pr.id) RETURNING cert_no, id INTO cert, oid;
    INSERT INTO app.id_photos(once_id,mime,data) VALUES (oid,p_photo_mime,p_photo);
  EXCEPTION WHEN unique_violation THEN            -- two requests at the same moment: the DB still allows only one
    SELECT cert_no INTO prev FROM app.once_orders WHERE phone_hash=hp OR id_number_hash=hi LIMIT 1;
    RETURN jsonb_build_object('status','used','cert_no',prev);
  END;
  INSERT INTO app.telegram_outbox(kind,ref_no,payload) VALUES ('once',cert,
    jsonb_build_object('cert_no',cert,'him',btrim(p_him),'her',btrim(p_her),'phone',ph,'product',pr.name_ar));
  RETURN jsonb_build_object('status','ok','cert_no',cert);
END $$;

-- bot worker: claim up to n unsent messages (skips rows another worker holds), then mark them sent.
CREATE FUNCTION api.outbox_claim(n int DEFAULT 10) RETURNS SETOF app.telegram_outbox LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  UPDATE app.telegram_outbox o SET locked_at=now(), attempts=o.attempts+1
  WHERE o.id IN (SELECT id FROM app.telegram_outbox WHERE sent_at IS NULL AND attempts < 8
                   AND (locked_at IS NULL OR locked_at < now()-interval '2 minutes')
                 ORDER BY created_at LIMIT n FOR UPDATE SKIP LOCKED)
  RETURNING o.*
$$;
CREATE FUNCTION api.outbox_done(p_id bigint) RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  UPDATE app.telegram_outbox SET sent_at=now(), locked_at=NULL WHERE id=p_id
$$;

-- ID photo for the owner's Telegram verification message (worker only), and purge after N days
CREATE FUNCTION api.id_photo(p_cert int) RETURNS TABLE(mime text, data bytea) LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT ph.mime, ph.data FROM app.id_photos ph JOIN app.once_orders o ON o.id=ph.once_id WHERE o.cert_no=p_cert
$$;
CREATE FUNCTION api.purge_id_photos(days int DEFAULT 30) RETURNS int LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE n int;
BEGIN
  WITH d AS (DELETE FROM app.id_photos WHERE created_at < now()-make_interval(days=>days) RETURNING once_id)
  UPDATE app.once_orders o SET id_purged_at=now() FROM d WHERE o.id=d.once_id;
  GET DIAGNOSTICS n = ROW_COUNT;
  RETURN n;
END $$;

-- ───────────────────────── admin API ─────────────────────────
CREATE FUNCTION api.admin_orders(p_status text DEFAULT NULL, p_limit int DEFAULT 50)
RETURNS TABLE(order_no bigint,status text,created_at timestamptz,name text,phone text,governorate text,address text,note text,product text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT o.order_no,o.status::text,o.created_at,c.name,c.phone,g.name_ar,o.address,o.note,p.name_ar
  FROM app.orders o JOIN app.customers c ON c.id=o.customer_id JOIN app.products p ON p.id=o.product_id JOIN app.governorates g ON g.code=o.governorate
  WHERE p_status IS NULL OR o.status::text=p_status ORDER BY o.created_at DESC LIMIT least(p_limit,500)
$$;
CREATE FUNCTION api.admin_set_status(p_order_no bigint, p_status text, p_actor text) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  PERFORM set_config('app.actor', p_actor, true);
  UPDATE app.orders SET status=p_status::app.order_status WHERE order_no=p_order_no;
  IF NOT FOUND THEN RAISE EXCEPTION 'NO_ORDER' USING ERRCODE='P0404'; END IF;
END $$;
CREATE FUNCTION api.admin_upsert_product(p jsonb, p_actor text) RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  PERFORM set_config('app.actor', p_actor, true);
  INSERT INTO app.products(slug,type,name_ar,name_en,description,specs,weight_g,price_iqd,images,is_active,sort)
  VALUES (p->>'slug',(p->>'type')::app.product_type,p->>'name_ar',p->>'name_en',coalesce(p->>'description',''),
          coalesce(ARRAY(SELECT jsonb_array_elements_text(p->'specs')),'{}'),(p->>'weight_g')::numeric,(p->>'price_iqd')::int,
          coalesce(ARRAY(SELECT jsonb_array_elements_text(p->'images')),'{}'),coalesce((p->>'is_active')::boolean,true),coalesce((p->>'sort')::int,0))
  ON CONFLICT (slug) DO UPDATE SET type=EXCLUDED.type,name_ar=EXCLUDED.name_ar,name_en=EXCLUDED.name_en,description=EXCLUDED.description,
     specs=EXCLUDED.specs,weight_g=EXCLUDED.weight_g,price_iqd=EXCLUDED.price_iqd,images=EXCLUDED.images,is_active=EXCLUDED.is_active,sort=EXCLUDED.sort;
  RETURN p->>'slug';
END $$;

RESET ROLE;

-- ───────────────────────── grants: functions only ─────────────────────────
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA api FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA app FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA audit FROM PUBLIC;
GRANT EXECUTE ON FUNCTION api.norm_phone(text), api.list_products(),
  api.place_order(text,text,text,text,text,text,inet),
  api.place_once(text,text,text,text,text,bytea,text,text,inet),
  api.outbox_claim(int), api.outbox_done(bigint),
  api.id_photo(int), api.purge_id_photos(int) TO sc_api;
GRANT EXECUTE ON FUNCTION api.list_products(), api.admin_orders(text,int),
  api.admin_set_status(bigint,text,text), api.admin_upsert_product(jsonb,text) TO sc_admin;
ALTER DEFAULT PRIVILEGES FOR ROLE sc_owner REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

COMMIT;
