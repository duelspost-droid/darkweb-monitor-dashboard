-- 005: 관리자 전용 잠금 — 공개 읽기 제거, 로그인(authenticated)만 조회 가능.
--  - 3개 테이블의 SELECT 정책을 public → authenticated 로 변경
--  - breach_findings 에 account(식별/full) 컬럼 추가 (회사 소유 계정 한정, 인증 뒤에만 노출)
--  쓰기(service_role)는 그대로. anon 키로는 더 이상 데이터를 못 읽는다(RLS 거부).

-- breach_findings: 공개 읽기 제거 → 로그인만
DROP POLICY IF EXISTS breach_findings_read ON breach_findings;
CREATE POLICY breach_findings_read ON breach_findings
  FOR SELECT TO authenticated USING (true);

ALTER TABLE breach_findings ADD COLUMN IF NOT EXISTS account TEXT; -- 식별(full). 회사 계정만.

-- scan_runs: 로그인만
DROP POLICY IF EXISTS scan_runs_read ON scan_runs;
CREATE POLICY scan_runs_read ON scan_runs
  FOR SELECT TO authenticated USING (true);

-- infostealer_findings: 로그인만
DROP POLICY IF EXISTS infostealer_read ON infostealer_findings;
CREATE POLICY infostealer_read ON infostealer_findings
  FOR SELECT TO authenticated USING (true);
