-- 004: 다크웹 인포스틸러(도메인 전수) + 수집 출처 기록.
--  - breach_findings 에 source(수집 출처) 컬럼 추가
--  - infostealer_findings: Hudson Rock Cavalier 도메인 전수 집계(무료, 키 불필요)
--  - 개인정보: 도메인 단위 집계 + 영향 URL 만 저장(개별 계정 미저장)

-- breach_findings 출처 기록
ALTER TABLE breach_findings ADD COLUMN IF NOT EXISTS source TEXT;

-- 인포스틸러 감염 (도메인 단위)
CREATE TABLE IF NOT EXISTS infostealer_findings (
  domain        TEXT PRIMARY KEY,
  source        TEXT NOT NULL DEFAULT 'Hudson Rock Cavalier',
  total         INT NOT NULL DEFAULT 0,   -- 도메인 관련 감염 총계
  employees     INT NOT NULL DEFAULT 0,   -- 임직원(도메인 메일) 감염
  users         INT NOT NULL DEFAULT 0,   -- 사용자/고객 감염
  third_parties INT NOT NULL DEFAULT 0,   -- 서드파티 감염
  affected_urls JSONB DEFAULT '[]',       -- 영향받은 URL Top(로그인 페이지 등)
  scanned_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

DROP TRIGGER IF EXISTS trg_infostealer_updated ON infostealer_findings;
CREATE TRIGGER trg_infostealer_updated
  BEFORE UPDATE ON infostealer_findings
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

ALTER TABLE infostealer_findings ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS infostealer_read ON infostealer_findings;
CREATE POLICY infostealer_read ON infostealer_findings
  FOR SELECT USING (true);            -- 집계는 공개 읽기

DROP POLICY IF EXISTS infostealer_write ON infostealer_findings;
CREATE POLICY infostealer_write ON infostealer_findings
  FOR ALL TO service_role USING (true) WITH CHECK (true);

-- scan_runs 에 수집 출처 기록(provenance)
ALTER TABLE scan_runs ADD COLUMN IF NOT EXISTS sources JSONB DEFAULT '[]';
