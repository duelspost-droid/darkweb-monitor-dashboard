-- 016: is_new(신규) 안정화 — 영속 first-seen 추적.
-- 문제: breach_findings 는 매 스캔 stale-delete 로 churn 한다. 소스가 rate-limit/timeout 으로
--       매 런마다 완전히 같은 집합을 못 걷어, 이번에 안 걷힌 유출은 삭제됐다가 다음 런에 재수집된다.
--       그때 is_new(=현재 DB에 finding_id 없음)가 다시 true → 같은 유출이 매번 '신규'로 뜬다.
-- 해결: finding_seen(append-only)에 '한 번이라도 본 finding_id'를 영속 기록.
--       is_new = finding_seen 에 없을 때만 → 삭제됐다 재수집돼도 신규 아님.
-- 접근: Edge Function(service_role) 만 읽고 쓴다(프런트 미참조). RLS on + 정책 없음 = service_role 만.

CREATE TABLE IF NOT EXISTS finding_seen (
  finding_id    TEXT PRIMARY KEY,
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE finding_seen ENABLE ROW LEVEL SECURITY;

-- 현재 breach_findings 를 시드 — 마이그 직후 스캔에서 기존 유출이 전부 '신규'로 쏟아지는 것 방지.
INSERT INTO finding_seen (finding_id)
SELECT finding_id FROM breach_findings
ON CONFLICT (finding_id) DO NOTHING;
