-- 011: 관리자 이메일 화이트리스트 — '로그인만 하면 누구나'에서 '승인된 관리자만'으로.
-- 배경: 005/006/008 의 SELECT 정책이 전부 `authenticated USING(true)` 라, anon 키(클라이언트 번들 공개)로
--       임의 계정이 하나라도 생기면(또는 self-signup ON) 감염호스트·full 계정 등 고민감 데이터를 통째로 읽을 수 있었다.
--       JWT 이메일을 화이트리스트로 강제해 접근 주체를 명시적으로 한정한다(최소권한).
-- service_role(배치 적재)와 set_remediation 등 SECURITY DEFINER RPC 는 RLS 우회라 영향 없음.

CREATE TABLE IF NOT EXISTS admin_allowlist (
  email      TEXT PRIMARY KEY,
  note       TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE admin_allowlist ENABLE ROW LEVEL SECURITY;
-- admin_allowlist 자체는 authenticated 직접 읽기 불가(목록 노출 방지). is_admin() 이 정의자 권한으로만 조회.

-- 승인 관리자 seed (기본 관리자). 추가 시 INSERT 만 하면 됨.
INSERT INTO admin_allowlist(email, note) VALUES ('duels@jbfg.com', '기본 관리자')
  ON CONFLICT (email) DO NOTHING;

-- 헬퍼: 현재 JWT 이메일이 화이트리스트에 있는지. SECURITY DEFINER 로 admin_allowlist RLS 우회.
CREATE OR REPLACE FUNCTION is_admin() RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (SELECT 1 FROM admin_allowlist WHERE email = auth.jwt() ->> 'email');
$$;
REVOKE ALL ON FUNCTION is_admin() FROM public;
GRANT EXECUTE ON FUNCTION is_admin() TO authenticated;

-- SELECT 정책을 화이트리스트(is_admin)로 교체.
DROP POLICY IF EXISTS breach_findings_read ON breach_findings;
CREATE POLICY breach_findings_read ON breach_findings FOR SELECT TO authenticated USING (is_admin());

DROP POLICY IF EXISTS scan_runs_read ON scan_runs;
CREATE POLICY scan_runs_read ON scan_runs FOR SELECT TO authenticated USING (is_admin());

DROP POLICY IF EXISTS infostealer_read ON infostealer_findings;
CREATE POLICY infostealer_read ON infostealer_findings FOR SELECT TO authenticated USING (is_admin());

DROP POLICY IF EXISTS infostealer_hosts_read ON infostealer_hosts;
CREATE POLICY infostealer_hosts_read ON infostealer_hosts FOR SELECT TO authenticated USING (is_admin());

DROP POLICY IF EXISTS remediation_log_read ON remediation_log;
CREATE POLICY remediation_log_read ON remediation_log FOR SELECT TO authenticated USING (is_admin());
