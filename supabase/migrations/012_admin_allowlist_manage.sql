-- 012: admin_allowlist 관리 UI용 RLS — 승인 관리자가 다른 관리자를 조회/추가/삭제.
-- 011 에서 admin_allowlist 는 RLS on + authenticated 정책 없음(is_admin() 정의자 조회만) 상태였다.
-- 대시보드 UI 에서 관리하려면 authenticated(관리자) 정책이 필요하다.
--  · 조회/추가: is_admin() (승인 관리자만)
--  · 삭제: is_admin() AND 자기 자신 제외 → 자가 잠금(최소 1명) 방지.
-- 주의: allowlist 는 '데이터 접근 권한'만 부여. 실제 로그인은 해당 이메일의 Supabase Auth 계정이 별도 필요.

DROP POLICY IF EXISTS admin_allowlist_read ON admin_allowlist;
CREATE POLICY admin_allowlist_read ON admin_allowlist
  FOR SELECT TO authenticated USING (is_admin());

DROP POLICY IF EXISTS admin_allowlist_insert ON admin_allowlist;
CREATE POLICY admin_allowlist_insert ON admin_allowlist
  FOR INSERT TO authenticated WITH CHECK (is_admin());

DROP POLICY IF EXISTS admin_allowlist_delete ON admin_allowlist;
CREATE POLICY admin_allowlist_delete ON admin_allowlist
  FOR DELETE TO authenticated
  USING (is_admin() AND email <> (auth.jwt() ->> 'email'));
