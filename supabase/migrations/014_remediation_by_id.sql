-- 014: 건별(finding_id) 조치 RPC.
-- 소스코드 노출·고객 개인정보 노출은 account_masked='*@domain' 을 여러 건이 공유하므로
-- 계정단위 set_remediation 으로는 개별 처리가 안 된다. finding_id 단위로 조치한다.
-- set_remediation 과 동일하게 status/메모/actor 기록 + remediation_log 적재. is_admin() 게이트 명시.

CREATE OR REPLACE FUNCTION set_remediation_by_id(p_finding_id TEXT, p_status TEXT, p_note TEXT)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_actor TEXT := COALESCE(auth.jwt() ->> 'email', 'unknown');
  v_account TEXT;
  v_domain TEXT;
BEGIN
  IF NOT is_admin() THEN
    RAISE EXCEPTION 'not authorized';
  END IF;
  IF p_status NOT IN ('open', 'remediated', 'dismissed') THEN
    RAISE EXCEPTION 'invalid status: %', p_status;
  END IF;
  UPDATE breach_findings
     SET status = p_status,
         remediation_note = p_note,
         remediated_at = CASE WHEN p_status = 'open' THEN NULL ELSE now() END,
         remediated_by = CASE WHEN p_status = 'open' THEN NULL ELSE v_actor END
   WHERE finding_id = p_finding_id
   RETURNING account_masked, domain INTO v_account, v_domain;
  INSERT INTO remediation_log(account_masked, domain, status, note, actor)
  VALUES (COALESCE(v_account, p_finding_id), v_domain, p_status, p_note, v_actor);
END; $$;

REVOKE ALL ON FUNCTION set_remediation_by_id(TEXT, TEXT, TEXT) FROM public;
GRANT EXECUTE ON FUNCTION set_remediation_by_id(TEXT, TEXT, TEXT) TO authenticated;
