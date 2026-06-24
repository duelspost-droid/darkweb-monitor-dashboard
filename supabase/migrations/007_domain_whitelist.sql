-- 007_domain_whitelist.sql
-- #3 도메인 화이트리스트 DB 제약 — 앱 가드(plausibleEmail/endsWith) + DB 이중 방어.
-- breach_findings / infostealer_findings / infostealer_hosts 의 domain 을 JB 4개 계열사로 강제.
-- 4개 외 도메인이 어떤 경로로도 적재되지 못하게 막는다(설계문서 P 항목 반영).
--
-- not valid → validate 패턴: 풀테이블 락 없이 추가 후 기존 행을 별도 검증.
-- 기존 데이터가 위반하면 validate 단계에서 실패하므로(현재는 4개 도메인뿐이라 통과) 안전.
-- 도메인이 바뀌면 이 제약을 drop/recreate 해야 함(의도된 강한 게이트).

do $$
declare
  d_list constant text[] := array['jbfg.com', 'jbbank.co.kr', 'kjbank.com', 'wooricap.com'];
begin
  -- breach_findings
  if not exists (select 1 from pg_constraint where conname = 'breach_findings_domain_whitelist') then
    alter table public.breach_findings
      add constraint breach_findings_domain_whitelist
      check (domain = any (array['jbfg.com', 'jbbank.co.kr', 'kjbank.com', 'wooricap.com'])) not valid;
    alter table public.breach_findings validate constraint breach_findings_domain_whitelist;
  end if;

  -- infostealer_findings (도메인 단위 집계)
  if to_regclass('public.infostealer_findings') is not null
     and not exists (select 1 from pg_constraint where conname = 'infostealer_findings_domain_whitelist') then
    alter table public.infostealer_findings
      add constraint infostealer_findings_domain_whitelist
      check (domain = any (array['jbfg.com', 'jbbank.co.kr', 'kjbank.com', 'wooricap.com'])) not valid;
    alter table public.infostealer_findings validate constraint infostealer_findings_domain_whitelist;
  end if;

  -- infostealer_hosts (감염 호스트 상세)
  if to_regclass('public.infostealer_hosts') is not null
     and not exists (select 1 from pg_constraint where conname = 'infostealer_hosts_domain_whitelist') then
    alter table public.infostealer_hosts
      add constraint infostealer_hosts_domain_whitelist
      check (domain = any (array['jbfg.com', 'jbbank.co.kr', 'kjbank.com', 'wooricap.com'])) not valid;
    alter table public.infostealer_hosts validate constraint infostealer_hosts_domain_whitelist;
  end if;

  raise notice 'domain whitelist constraints ensured for: %', d_list;
end $$;
