-- 다크웹/유출 계정 모니터링 결과 저장 테이블.
-- 개인정보 제약: 계정은 항상 마스킹(account_masked, 예 "jo***@domain")으로만 저장한다.
-- 평문 비밀번호·전체 이메일·기타 개인식별자는 저장하지 않는다.

CREATE TABLE IF NOT EXISTS breach_findings (
  finding_id   TEXT PRIMARY KEY,             -- domain|alias|breach 해시(평문 미저장)
  account_masked TEXT NOT NULL,              -- 마스킹된 계정만
  domain       TEXT NOT NULL,
  breach_name  TEXT NOT NULL,
  breach_title TEXT,
  breach_date  DATE,
  data_classes TEXT[] DEFAULT '{}',          -- 노출 항목 분류(값 자체는 미저장)
  severity     TEXT NOT NULL DEFAULT 'low',  -- critical | high | medium | low
  discovered_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_breach_findings_domain ON breach_findings (domain);
CREATE INDEX IF NOT EXISTS idx_breach_findings_severity ON breach_findings (severity);

-- RLS: 읽기는 공개(집계·마스킹만), 쓰기는 service_role(배치) 전용.
ALTER TABLE breach_findings ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS breach_findings_read ON breach_findings;
CREATE POLICY breach_findings_read ON breach_findings
  FOR SELECT USING (true);

DROP POLICY IF EXISTS breach_findings_write ON breach_findings;
CREATE POLICY breach_findings_write ON breach_findings
  FOR ALL TO service_role USING (true) WITH CHECK (true);
