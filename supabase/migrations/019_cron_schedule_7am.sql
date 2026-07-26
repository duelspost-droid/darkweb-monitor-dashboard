-- 019: 배치 스케줄 자정(KST) → 새벽 7시(KST)로 이동.
-- jobid=1 (daily-breach-scan)이 유출 스캔 + 보안 뉴스를 함께 수집한다.
-- 07:00 KST 실행 = 출근 시점에 그날 최신 데이터. 22:00 UTC = 07:00 KST(UTC+9).
-- 프런트 문구("매일 새벽 7시 자동 갱신")와 실제 크론을 일치시키는 변경.
--
-- ⚠️ 적용법: Supabase SQL Editor 에 붙여넣고 Run (에이전트는 auto모드 분류기가
--    프로덕션 cron 변경을 차단해 직접 실행 불가 → 소유자 직접 Run).
-- 확인: select jobid, schedule, active from cron.job where jobid = 1;  → '0 22 * * *'

SELECT cron.alter_job(1, schedule => '0 22 * * *');
