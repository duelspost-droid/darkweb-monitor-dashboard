-- 003: 매일 자정(KST) scan-breaches Edge Function 자동 호출.
--  - pg_cron: 스케줄러
--  - pg_net: DB에서 HTTP 호출
--  - 시크릿(프로젝트 URL·service_role 키)은 Vault 에 저장(이 마이그레이션엔 평문 미포함).
--
-- ⚠️ 적용 전 Vault 시크릿 2개를 먼저 등록해야 한다(프로젝트별 1회, 커밋 금지):
--    select vault.create_secret('https://<ref>.supabase.co', 'project_url');
--    select vault.create_secret('<SCAN_SECRET>',             'scan_secret');
--  (<SCAN_SECRET> 은 Edge Function 시크릿과 동일 값. Supabase Studio SQL Editor 에서 실행)
--  Edge Function 은 verify_jwt=false + x-scan-secret 헤더로 보호되므로 service_role 키 불필요.

-- Supabase 에선 스키마 강제 없이 생성(pg_cron→cron, pg_net→net 스키마). 대시보드에서 미리 켜져 있으면 no-op.
CREATE EXTENSION IF NOT EXISTS pg_cron;
CREATE EXTENSION IF NOT EXISTS pg_net;

-- 기존 동일 잡 제거(재적용 안전)
SELECT cron.unschedule('daily-breach-scan')
WHERE EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'daily-breach-scan');

-- 매일 15:00 UTC = 00:00 KST
SELECT cron.schedule(
  'daily-breach-scan',
  '0 15 * * *',
  $$
  SELECT net.http_post(
    url := (SELECT decrypted_secret FROM vault.decrypted_secrets WHERE name = 'project_url')
           || '/functions/v1/scan-breaches',
    headers := jsonb_build_object(
      'Content-Type', 'application/json',
      'x-scan-secret', (SELECT decrypted_secret FROM vault.decrypted_secrets WHERE name = 'scan_secret')
    ),
    body := '{}'::jsonb,
    timeout_milliseconds := 120000
  );
  $$
);
