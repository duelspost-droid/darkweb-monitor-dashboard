-- 006: 인포스틸러 감염 호스트(피해자) 상세 — 관리자 인증 후에만 조회.
--  - Hudson Rock Cavalier search-by-email 의 stealers[] 호스트 단위 상세를 보관.
--  - 민감정보: top_passwords/top_logins/ip 는 Hudson Rock 이 이미 부분 마스킹해 반환한 값만 저장한다
--    (평문 비밀번호·전체 IP 미저장). 그래도 민감하므로 RLS 로 authenticated(관리자)만 읽는다.

CREATE TABLE IF NOT EXISTS infostealer_hosts (
  host_id                  TEXT PRIMARY KEY,          -- 해시(account|computer|date|ip) — 중복 제거 키
  account_masked           TEXT NOT NULL,             -- 마스킹된 계정 (jo***@domain)
  domain                   TEXT NOT NULL,
  computer_name            TEXT,                      -- 감염 PC 이름
  operating_system         TEXT,                      -- OS
  ip                       TEXT,                      -- 부분 마스킹 IP (예 103.132.***.***)
  date_compromised         DATE,                      -- 감염 일자
  stealer_family           TEXT,                      -- 스틸러 종류(Redline/Acreed 등)
  malware_path             TEXT,                      -- 악성코드 실행 경로
  antiviruses              JSONB DEFAULT '[]',        -- 감염 당시 설치 백신
  total_corporate_services INT NOT NULL DEFAULT 0,    -- 탈취된 사내 서비스 수
  total_user_services      INT NOT NULL DEFAULT 0,    -- 탈취된 개인 서비스 수
  top_passwords            JSONB DEFAULT '[]',        -- 부분 마스킹 비번 샘플(평문 아님)
  top_logins               JSONB DEFAULT '[]',        -- 부분 마스킹 로그인 샘플
  last_scan_tag            TEXT,                      -- 이번 스캔 태그(stale 정리용)
  scanned_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at               TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_infostealer_hosts_domain ON infostealer_hosts (domain);
CREATE INDEX IF NOT EXISTS idx_infostealer_hosts_date ON infostealer_hosts (date_compromised DESC);

ALTER TABLE infostealer_hosts ENABLE ROW LEVEL SECURITY;

-- 읽기: 로그인(관리자)만 — 호스트 상세는 민감.
DROP POLICY IF EXISTS infostealer_hosts_read ON infostealer_hosts;
CREATE POLICY infostealer_hosts_read ON infostealer_hosts
  FOR SELECT TO authenticated USING (true);

-- 쓰기: 배치(service_role)만.
DROP POLICY IF EXISTS infostealer_hosts_write ON infostealer_hosts;
CREATE POLICY infostealer_hosts_write ON infostealer_hosts
  FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP TRIGGER IF EXISTS trg_infostealer_hosts_updated ON infostealer_hosts;
CREATE TRIGGER trg_infostealer_hosts_updated
  BEFORE UPDATE ON infostealer_hosts
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();
