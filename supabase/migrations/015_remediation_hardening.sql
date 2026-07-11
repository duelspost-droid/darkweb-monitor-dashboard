-- 015: 조치 RPC 하드닝 (멀티에이전트 검증 후속).
--  (a) set_remediation(계정단위)에 is_admin() 게이트 추가 — 기존엔 authenticated 면 누구나 호출 가능했음
--      (RLS 로 데이터 READ 는 is_admin 이 막지만, SECURITY DEFINER RPC 는 우회 → 방어심층).
--  (b) set_remediation_by_id 감사로그를 공유 account_masked('*@domain') 대신 breach_title(레포/건 식별)로
--      적재해 '조치 변경 이력'에서 어느 노출을 조치했는지 구분되게 + 미존재 finding_id 방어(RAISE).
-- 둘 다 CREATE OR REPLACE (멱등) · 값/PII 미기록(breach_title 은 이메일 제외·레포/경로만).

-- (a) 계정단위 set_remediation — is_admin() 게이트 추가 -----------------------------------
CREATE OR REPLACE FUNCTION set_remediation(p_account TEXT, p_status TEXT, p_note TEXT)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_actor TEXT := COALESCE(auth.jwt() ->> 'email', 'unknown');
  v_domain TEXT;
BEGIN
  IF NOT is_admin() THEN RAISE EXCEPTION 'not authorized'; END IF;
  IF p_status NOT IN ('open', 'remediated', 'dismissed') THEN
    RAISE EXCEPTION 'invalid status: %', p_status;
  END IF;
  UPDATE breach_findings
     SET status = p_status,
         remediation_note = p_note,
         remediated_at = CASE WHEN p_status = 'open' THEN NULL ELSE now() END,
         remediated_by = CASE WHEN p_status = 'open' THEN NULL ELSE v_actor END
   WHERE account_masked = p_account;
  SELECT domain INTO v_domain FROM breach_findings WHERE account_masked = p_account LIMIT 1;
  INSERT INTO remediation_log(account_masked, domain, status, note, actor)
  VALUES (p_account, v_domain, p_status, p_note, v_actor);
END; $$;
REVOKE ALL ON FUNCTION set_remediation(TEXT, TEXT, TEXT) FROM public;
GRANT EXECUTE ON FUNCTION set_remediation(TEXT, TEXT, TEXT) TO authenticated;

-- (b) 건단위 set_remediation_by_id — 감사로그 식별성 개선 + 미존재 방어 -----------------------
CREATE OR REPLACE FUNCTION set_remediation_by_id(p_finding_id TEXT, p_status TEXT, p_note TEXT)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_actor TEXT := COALESCE(auth.jwt() ->> 'email', 'unknown');
  v_account TEXT;
  v_domain TEXT;
  v_title TEXT;
BEGIN
  IF NOT is_admin() THEN RAISE EXCEPTION 'not authorized'; END IF;
  IF p_status NOT IN ('open', 'remediated', 'dismissed') THEN
    RAISE EXCEPTION 'invalid status: %', p_status;
  END IF;
  UPDATE breach_findings
     SET status = p_status,
         remediation_note = p_note,
         remediated_at = CASE WHEN p_status = 'open' THEN NULL ELSE now() END,
         remediated_by = CASE WHEN p_status = 'open' THEN NULL ELSE v_actor END
   WHERE finding_id = p_finding_id
   RETURNING account_masked, domain, breach_title INTO v_account, v_domain, v_title;
  IF NOT FOUND THEN RAISE EXCEPTION 'finding not found: %', p_finding_id; END IF;
  -- 노출건은 account_masked 를 공유하므로 breach_title(레포/경로 — 이메일값 아님)을 식별자로 기록.
  INSERT INTO remediation_log(account_masked, domain, status, note, actor)
  VALUES (COALESCE(v_title, v_account, p_finding_id), v_domain, p_status, p_note, v_actor);
END; $$;
REVOKE ALL ON FUNCTION set_remediation_by_id(TEXT, TEXT, TEXT) FROM public;
GRANT EXECUTE ON FUNCTION set_remediation_by_id(TEXT, TEXT, TEXT) TO authenticated;
