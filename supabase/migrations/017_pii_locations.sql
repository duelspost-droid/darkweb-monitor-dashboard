-- 017: 고객 개인정보 노출 위치 — 카테고리별 라인번호 저장.
-- 목적: "어느 URL 어느 부분(라인)에 있는지" 대시보드 표시(GitHub 딥링크 url#L<line>).
-- 안전: 실제 값·주변 문맥은 저장 안 함. [{ "category": "...", "lines": [12, 48] }] 형태만.
ALTER TABLE breach_findings ADD COLUMN IF NOT EXISTS pii_locations jsonb;
