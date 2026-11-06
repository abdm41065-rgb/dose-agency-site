"""PRE_DEPLOY job on DigitalOcean: apply schema once, (re)set the API login password, seed products if empty.
Env: ADMIN_DATABASE_URL (doadmin, from the managed DB binding), SC_API_PASSWORD (secret)."""
import json, os, psycopg
HERE = os.path.dirname(os.path.abspath(__file__))
with psycopg.connect(os.environ['ADMIN_DATABASE_URL'], autocommit=True) as c:
    if not c.execute("SELECT 1 FROM pg_namespace WHERE nspname='app'").fetchone():
        c.execute(open(os.path.join(HERE, 'schema.sql'), encoding='utf-8').read()); print('schema applied')
    c.execute("DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='sc_api_login') THEN CREATE ROLE sc_api_login LOGIN; END IF; END $$")
    c.execute(psycopg.sql.SQL('ALTER ROLE sc_api_login WITH LOGIN PASSWORD {}').format(psycopg.sql.Literal(os.environ['SC_API_PASSWORD'])))
    c.execute('GRANT sc_api TO sc_api_login')
    c.execute(psycopg.sql.SQL('GRANT sc_admin TO {}').format(psycopg.sql.Identifier(c.execute('SELECT current_user').fetchone()[0])))
    if c.execute('SELECT count(*) FROM api.list_products()').fetchone()[0] == 0:
        for p in json.load(open(os.path.join(HERE, 'products.json'), encoding='utf-8')):
            c.execute('SELECT api.admin_upsert_product(%s::jsonb,%s)', (json.dumps(p, ensure_ascii=False), 'seed'))
        print('products seeded')
print('migrate ok')
