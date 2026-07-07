-- 013: 009(app_users) 되돌림 — 011/012 의 admin_allowlist 체계와 충돌 발견.
--   009 가 breach_findings_read 등 SELECT 정책을 is_approved_user() 로 교체해
--   011 이 이미 적용해둔 is_admin()(admin_allowlist 기반) 정책을 덮어썼다.
--   또한 009 의 "셀프가입 후 대기" 모델은 011 의 설계 의도
--   ("임의 계정이 생기면 감염호스트 등 고민감 데이터를 통째로 읽을 수 있다" → 화이트리스트로 한정)와 충돌한다.
--   → SELECT 정책을 011 상태(is_admin())로 복원하고, set_remediation 가드도 is_admin()으로 되돌리고,
--     009 가 만든 app_users/트리거/RPC/헬퍼는 정리(DROP)한다. admin_allowlist 는 그대로 유지.

-- 1) SELECT 정책 복원 (011 과 동일 정의로 재적용 — 정책명 동일이라 CREATE 가 교체) ---------
DROP POLICY IF EXISTS breach_findings_read ON public.breach_findings;
CREATE POLICY breach_findings_read ON public.breach_findings FOR SELECT TO authenticated USING (is_admin());
DROP POLICY IF EXISTS scan_runs_read ON public.scan_runs;
CREATE POLICY scan_runs_read ON public.scan_runs FOR SELECT TO authenticated USING (is_admin());
DROP POLICY IF EXISTS infostealer_read ON public.infostealer_findings;
CREATE POLICY infostealer_read ON public.infostealer_findings FOR SELECT TO authenticated USING (is_admin());
DROP POLICY IF EXISTS infostealer_hosts_read ON public.infostealer_hosts;
CREATE POLICY infostealer_hosts_read ON public.infostealer_hosts FOR SELECT TO authenticated USING (is_admin());
DROP POLICY IF EXISTS remediation_log_read ON public.remediation_log;
CREATE POLICY remediation_log_read ON public.remediation_log FOR SELECT TO authenticated USING (is_admin());
DROP POLICY IF EXISTS remediation_log_write ON public.remediation_log;
CREATE POLICY remediation_log_write ON public.remediation_log FOR INSERT TO authenticated WITH CHECK (is_admin());

-- 2) set_remediation 가드를 is_admin() 으로 복원(008 정의로) -----------------------------
CREATE OR REPLACE FUNCTION set_remediation(p_account TEXT, p_status TEXT, p_note TEXT)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
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
   WHERE account_masked = p_account;
  SELECT domain INTO v_domain FROM breach_findings WHERE account_masked = p_account LIMIT 1;
  INSERT INTO remediation_log(account_masked, domain, status, note, actor)
  VALUES (p_account, v_domain, p_status, p_note, v_actor);
END; $$;
REVOKE ALL ON FUNCTION set_remediation(TEXT, TEXT, TEXT) FROM public;
GRANT EXECUTE ON FUNCTION set_remediation(TEXT, TEXT, TEXT) TO authenticated;

-- 3) 009 가 만든 app_users 관련 객체 정리 -------------------------------------------------
--    순서 중요: app_users 자체 정책(app_users_select)이 is_super_admin() 에 의존하므로
--    테이블(과 그 정책)을 먼저 지운 뒤에 독립 함수를 지운다.
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
DROP FUNCTION IF EXISTS public.handle_new_user();
DROP TABLE IF EXISTS public.app_users;
DROP FUNCTION IF EXISTS public.set_user_status(UUID, TEXT, TEXT);
DROP FUNCTION IF EXISTS public.set_user_role(UUID, TEXT);
DROP FUNCTION IF EXISTS public.is_approved_user();
DROP FUNCTION IF EXISTS public.is_super_admin();
