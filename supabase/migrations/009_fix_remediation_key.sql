-- 009: set_remediation 키 매칭 버그 수정.
-- 버그: 008의 RPC는 `WHERE account_masked = p_account` 로만 매칭했는데,
--       대시보드(fetchScan)는 그룹 키로 `account`(관리자=full 이메일)를 넘긴다.
--       breach_findings.account_masked 컬럼은 마스킹값('hi***@…')이라 full 이메일과 안 맞아
--       UPDATE 가 0행 → 조치 버튼이 "무반응"이었다.
-- 수정: full(account) 또는 masked(account_masked) 둘 다 매칭. (도메인단위 *@domain 도 커버)
CREATE OR REPLACE FUNCTION set_remediation(p_account TEXT, p_status TEXT, p_note TEXT)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_actor TEXT := COALESCE(auth.jwt() ->> 'email', 'unknown');
  v_domain TEXT;
BEGIN
  IF p_status NOT IN ('open', 'remediated', 'dismissed') THEN
    RAISE EXCEPTION 'invalid status: %', p_status;
  END IF;
  UPDATE breach_findings
     SET status = p_status,
         remediation_note = p_note,
         remediated_at = CASE WHEN p_status = 'open' THEN NULL ELSE now() END,
         remediated_by = CASE WHEN p_status = 'open' THEN NULL ELSE v_actor END
   WHERE account_masked = p_account OR account = p_account;  -- 핵심 수정: full/masked 둘 다
  SELECT domain INTO v_domain FROM breach_findings
   WHERE account_masked = p_account OR account = p_account LIMIT 1;
  INSERT INTO remediation_log(account_masked, domain, status, note, actor)
  VALUES (p_account, v_domain, p_status, p_note, v_actor);
END;
$$;
REVOKE ALL ON FUNCTION set_remediation(TEXT, TEXT, TEXT) FROM public;
GRANT EXECUTE ON FUNCTION set_remediation(TEXT, TEXT, TEXT) TO authenticated;
