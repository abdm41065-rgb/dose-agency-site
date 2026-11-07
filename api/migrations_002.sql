-- 002: drop national-ID lock; once orders are locked by phone only; photo = face selfie
BEGIN;
SET ROLE sc_owner;
DROP FUNCTION IF EXISTS api.place_once(text,text,text,text,text,bytea,text,text,inet);
ALTER TABLE app.once_orders DROP COLUMN IF EXISTS id_number_hash;
CREATE FUNCTION api.place_once(p_him text,p_her text,p_phone text,p_email text,p_photo bytea,p_photo_mime text,p_product text,p_ip inet)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE ph text := api.norm_phone(p_phone); hp bytea; cid bigint; pr app.products; cert int; prev int; oid bigint;
BEGIN
  IF ph IS NULL THEN RAISE EXCEPTION 'BAD_PHONE' USING ERRCODE='22023'; END IF;
  IF p_photo IS NULL THEN RAISE EXCEPTION 'NO_PHOTO' USING ERRCODE='22023'; END IF;
  IF NOT app.rate_ok('once:ip:'||host(p_ip),5,'1 hour') THEN RAISE EXCEPTION 'RATE_LIMIT' USING ERRCODE='P0429'; END IF;
  hp := app.hmac_of('phone:'||ph);
  SELECT cert_no INTO prev FROM app.once_orders WHERE phone_hash=hp;
  IF FOUND THEN RETURN jsonb_build_object('status','used','cert_no',prev); END IF;
  SELECT * INTO pr FROM app.products WHERE slug=p_product AND is_active;
  IF NOT FOUND THEN RAISE EXCEPTION 'BAD_PRODUCT' USING ERRCODE='22023'; END IF;
  INSERT INTO app.customers(name,phone,email) VALUES (btrim(p_him),ph,nullif(btrim(p_email),''))
    ON CONFLICT (phone) DO UPDATE SET email=coalesce(EXCLUDED.email,app.customers.email) RETURNING id INTO cid;
  BEGIN
    INSERT INTO app.once_orders(customer_id,phone_hash,him_name,her_name,product_id)
      VALUES (cid,hp,btrim(p_him),btrim(p_her),pr.id) RETURNING cert_no, id INTO cert, oid;
    INSERT INTO app.id_photos(once_id,mime,data) VALUES (oid,p_photo_mime,p_photo);
  EXCEPTION WHEN unique_violation THEN            -- two requests at the same moment: the DB still allows only one
    SELECT cert_no INTO prev FROM app.once_orders WHERE phone_hash=hp;
    RETURN jsonb_build_object('status','used','cert_no',prev);
  END;
  INSERT INTO app.telegram_outbox(kind,ref_no,payload) VALUES ('once',cert,
    jsonb_build_object('cert_no',cert,'him',btrim(p_him),'her',btrim(p_her),'phone',ph,'product',pr.name_ar));
  RETURN jsonb_build_object('status','ok','cert_no',cert);
END $$;
RESET ROLE;
REVOKE ALL ON FUNCTION api.place_once(text,text,text,text,bytea,text,text,inet) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION api.place_once(text,text,text,text,bytea,text,text,inet) TO sc_api;
COMMIT;
