-- 018: 보안 뉴스 — 매일 배치가 Google News RSS(금융·보안 이슈)에서 수집해 적재.
-- 목적: 담당자가 아침에 대시보드에서 최신 금융·보안 뉴스를 참고할 수 있게.
-- 저장 데이터는 전부 공개 뉴스(제목·링크·매체·분류·게시일) — 민감정보 없음.
-- 그래서 로그인 전(anon)에도 읽기 허용해 로그인 화면 미리보기로도 쓸 수 있게 한다.
-- 쓰기는 배치(service_role, RLS 우회)만 — SELECT 외 정책 없음 = anon/authenticated 쓰기 차단.

CREATE TABLE IF NOT EXISTS security_news (
  news_id      TEXT PRIMARY KEY,             -- Google 뉴스 기사 ID (여러 쿼리 간 중복 제거 키)
  title        TEXT NOT NULL,
  url          TEXT NOT NULL,                -- Google 뉴스 리다이렉트 URL(클릭 시 원문으로 이동)
  source       TEXT,                          -- 매체명(예: 보안뉴스, 데일리시큐)
  category     TEXT,                          -- 금융보안/개인정보/랜섬웨어/다크웹/취약점/사이버공격
  is_finance   BOOLEAN NOT NULL DEFAULT false,-- 금융 관련(우선 노출)
  published_at TIMESTAMPTZ,
  fetched_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE security_news ENABLE ROW LEVEL SECURITY;

-- 공개 뉴스이므로 anon 도 읽기 허용(로그인 전 미리보기용). 쓰기 정책 없음 → service_role 만 기록.
DROP POLICY IF EXISTS security_news_read ON security_news;
CREATE POLICY security_news_read ON security_news FOR SELECT TO anon, authenticated USING (true);

GRANT SELECT ON security_news TO anon, authenticated;

CREATE INDEX IF NOT EXISTS security_news_pub_idx ON security_news (published_at DESC);
