-- 002: Supabase 백엔드 확장.
--  - breach_findings 에 보강 컬럼 추가(is_new, password_risk, industry, reference_url, breach_logo)
--  - scan_runs: 스캔 실행 이력(대시보드 history·상태 표시용)
--  - 개인정보 제약: 평문 비밀번호·전체 이메일 미저장. 마스킹 계정만.

-- ── breach_findings 보강 컬럼 ──────────────────────────────────────────────
ALTER TABLE breach_findings ADD COLUMN IF NOT EXISTS is_new        BOOLEAN     DEFAULT false;
ALTER TABLE breach_findings ADD COLUMN IF NOT EXISTS password_risk TEXT;
ALTER TABLE breach_findings ADD COLUMN IF NOT EXISTS industry      TEXT;
ALTER TABLE breach_findings ADD COLUMN IF NOT EXISTS reference_url TEXT;
ALTER TABLE breach_findings ADD COLUMN IF NOT EXISTS breach_logo   TEXT;
-- 이번 스캔에서 본 항목 표시(이전 스캔에만 있던 항목 정리용). 값이 다르면 stale.
ALTER TABLE breach_findings ADD COLUMN IF NOT EXISTS last_scan_tag TEXT;

-- updated_at 자동 갱신 트리거
CREATE OR REPLACE FUNCTION set_updated_at() RETURNS trigger AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_breach_findings_updated ON breach_findings;
CREATE TRIGGER trg_breach_findings_updated
  BEFORE UPDATE ON breach_findings
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ── scan_runs: 스캔 실행 이력 ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scan_runs (
  id          BIGSERIAL PRIMARY KEY,
  scanned_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  source      TEXT,
  status      TEXT NOT NULL DEFAULT 'ok',   -- ok | error | no_source
  is_demo     BOOLEAN NOT NULL DEFAULT false,
  total       INT NOT NULL DEFAULT 0,
  new_count   INT NOT NULL DEFAULT 0,
  critical    INT NOT NULL DEFAULT 0,
  high        INT NOT NULL DEFAULT 0,
  medium      INT NOT NULL DEFAULT 0,
  low         INT NOT NULL DEFAULT 0,
  domains     TEXT[] DEFAULT '{}',
  note        TEXT
);

CREATE INDEX IF NOT EXISTS idx_scan_runs_scanned_at ON scan_runs (scanned_at DESC);

ALTER TABLE scan_runs ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS scan_runs_read ON scan_runs;
CREATE POLICY scan_runs_read ON scan_runs
  FOR SELECT USING (true);            -- 집계 이력은 공개 읽기

DROP POLICY IF EXISTS scan_runs_write ON scan_runs;
CREATE POLICY scan_runs_write ON scan_runs
  FOR ALL TO service_role USING (true) WITH CHECK (true);
