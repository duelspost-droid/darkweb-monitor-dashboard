-- 010: 인포스틸러 타임라인 — first_seen_at(최초 탐지) 추가 + 업데이트 시 보존.
-- 목적: "언제 노출/감염이 처음 잡혔는지"를 도메인·호스트 단위로 추적(관제 대응 타임라인).
-- 콜렉터 변경 불필요: 매 스캔 upsert(on_conflict)의 UPDATE 경로를 트리거로 보존, INSERT는 default now().

ALTER TABLE infostealer_findings ADD COLUMN IF NOT EXISTS first_seen_at TIMESTAMPTZ;
ALTER TABLE infostealer_hosts    ADD COLUMN IF NOT EXISTS first_seen_at TIMESTAMPTZ;

-- 기존 행 백필(현재 스캔시각을 최초탐지 하한으로). 호스트는 실제 감염일 우선.
UPDATE infostealer_findings SET first_seen_at = COALESCE(first_seen_at, scanned_at, now()) WHERE first_seen_at IS NULL;
UPDATE infostealer_hosts    SET first_seen_at = COALESCE(first_seen_at, date_compromised::timestamptz, scanned_at, now()) WHERE first_seen_at IS NULL;

-- 신규 INSERT 시 자동 채움.
ALTER TABLE infostealer_findings ALTER COLUMN first_seen_at SET DEFAULT now();
ALTER TABLE infostealer_hosts    ALTER COLUMN first_seen_at SET DEFAULT now();

-- UPDATE(매 스캔 upsert) 시 최초탐지 보존(덮어쓰기 방지).
CREATE OR REPLACE FUNCTION preserve_first_seen() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.first_seen_at IS NOT NULL THEN NEW.first_seen_at := OLD.first_seen_at; END IF;
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS trg_inf_findings_first_seen ON infostealer_findings;
CREATE TRIGGER trg_inf_findings_first_seen BEFORE UPDATE ON infostealer_findings
  FOR EACH ROW EXECUTE FUNCTION preserve_first_seen();

DROP TRIGGER IF EXISTS trg_inf_hosts_first_seen ON infostealer_hosts;
CREATE TRIGGER trg_inf_hosts_first_seen BEFORE UPDATE ON infostealer_hosts
  FOR EACH ROW EXECUTE FUNCTION preserve_first_seen();
