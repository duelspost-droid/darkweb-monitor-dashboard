-- 009: 다중 사용자 로그인 + 슈퍼관리자 승인/관리 워크플로.
--  - app_users: 역할(super_admin|general) + 상태(pending|approved|rejected|suspended)
--  - 신규 auth.users 가입 시 트리거로 app_users 행 자동 생성(pending/general)
--  - 데이터 열람 RLS 를 "승인된 사용자(is_approved_user)" 전용으로 강화(005/006/008 정책 교체)
--  - 승인/거부/정지·역할변경은 슈퍼관리자(is_super_admin) 전용 RPC (service_role 불필요)
--  - 계정 생성·비밀번호 지정/초기화·삭제는 Edge Function admin-users(service_role)에서 수행(여기 아님)
--  - 기존 관리자 duels@jbfg.com 을 슈퍼관리자(approved)로 시드, 나머지 기존 사용자는 pending 백필

-- 1) app_users -------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.app_users (
  id           UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  email        TEXT,
  role         TEXT NOT NULL DEFAULT 'general'  CHECK (role   IN ('super_admin','general')),
  status       TEXT NOT NULL DEFAULT 'pending'  CHECK (status IN ('pending','approved','rejected','suspended')),
  requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  decided_at   TIMESTAMPTZ,
  decided_by   TEXT,
  note         TEXT
);
ALTER TABLE public.app_users ENABLE ROW LEVEL SECURITY;

-- 2) 신규 가입 → app_users 자동 생성(pending/general) --------------------------
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  INSERT INTO public.app_users (id, email) VALUES (NEW.id, NEW.email)
  ON CONFLICT (id) DO NOTHING;
  RETURN NEW;
END; $$;
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- 3) 헬퍼(승인 여부 / 슈퍼관리자) — SECURITY DEFINER 로 app_users RLS 우회(재귀 방지) ----
CREATE OR REPLACE FUNCTION public.is_approved_user()
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (SELECT 1 FROM public.app_users WHERE id = auth.uid() AND status = 'approved');
$$;
CREATE OR REPLACE FUNCTION public.is_super_admin()
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (SELECT 1 FROM public.app_users WHERE id = auth.uid() AND role = 'super_admin' AND status = 'approved');
$$;

-- 4) app_users RLS: 본인 행 조회 / 슈퍼관리자는 전체 조회. (쓰기는 RPC·트리거·service_role만) ----
DROP POLICY IF EXISTS app_users_select ON public.app_users;
CREATE POLICY app_users_select ON public.app_users FOR SELECT TO authenticated
  USING (id = auth.uid() OR public.is_super_admin());
DROP POLICY IF EXISTS app_users_write ON public.app_users;
CREATE POLICY app_users_write ON public.app_users FOR ALL TO service_role USING (true) WITH CHECK (true);

-- 5) 승인/거부/정지 (슈퍼관리자 전용) ----------------------------------------
CREATE OR REPLACE FUNCTION public.set_user_status(p_user UUID, p_status TEXT, p_note TEXT DEFAULT NULL)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF NOT public.is_super_admin() THEN RAISE EXCEPTION '권한 없음: 슈퍼관리자만 가능'; END IF;
  IF p_status NOT IN ('approved','rejected','suspended','pending') THEN RAISE EXCEPTION '잘못된 상태: %', p_status; END IF;
  IF p_user = auth.uid() THEN RAISE EXCEPTION '본인 계정 상태는 변경할 수 없습니다'; END IF;
  UPDATE public.app_users
     SET status = p_status, decided_at = now(), decided_by = COALESCE(auth.jwt() ->> 'email','unknown'), note = COALESCE(p_note, note)
   WHERE id = p_user;
END; $$;
REVOKE ALL ON FUNCTION public.set_user_status(UUID, TEXT, TEXT) FROM public;
GRANT EXECUTE ON FUNCTION public.set_user_status(UUID, TEXT, TEXT) TO authenticated;

-- 6) 역할 변경 (슈퍼관리자 전용) --------------------------------------------
CREATE OR REPLACE FUNCTION public.set_user_role(p_user UUID, p_role TEXT)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF NOT public.is_super_admin() THEN RAISE EXCEPTION '권한 없음'; END IF;
  IF p_role NOT IN ('super_admin','general') THEN RAISE EXCEPTION '잘못된 역할: %', p_role; END IF;
  IF p_user = auth.uid() THEN RAISE EXCEPTION '본인 역할은 변경할 수 없습니다'; END IF;
  UPDATE public.app_users SET role = p_role WHERE id = p_user;
END; $$;
REVOKE ALL ON FUNCTION public.set_user_role(UUID, TEXT) FROM public;
GRANT EXECUTE ON FUNCTION public.set_user_role(UUID, TEXT) TO authenticated;

-- 7) 데이터 열람 RLS 강화: authenticated(USING true) → 승인된 사용자만(is_approved_user) ----
DROP POLICY IF EXISTS breach_findings_read ON public.breach_findings;
CREATE POLICY breach_findings_read ON public.breach_findings FOR SELECT TO authenticated USING (public.is_approved_user());
DROP POLICY IF EXISTS scan_runs_read ON public.scan_runs;
CREATE POLICY scan_runs_read ON public.scan_runs FOR SELECT TO authenticated USING (public.is_approved_user());
DROP POLICY IF EXISTS infostealer_read ON public.infostealer_findings;
CREATE POLICY infostealer_read ON public.infostealer_findings FOR SELECT TO authenticated USING (public.is_approved_user());
DROP POLICY IF EXISTS infostealer_hosts_read ON public.infostealer_hosts;
CREATE POLICY infostealer_hosts_read ON public.infostealer_hosts FOR SELECT TO authenticated USING (public.is_approved_user());
DROP POLICY IF EXISTS remediation_log_read ON public.remediation_log;
CREATE POLICY remediation_log_read ON public.remediation_log FOR SELECT TO authenticated USING (public.is_approved_user());
DROP POLICY IF EXISTS remediation_log_write ON public.remediation_log;
CREATE POLICY remediation_log_write ON public.remediation_log FOR INSERT TO authenticated WITH CHECK (public.is_approved_user());

-- 8) 조치 RPC 에 승인 가드 추가(미승인 사용자 조치 차단) — 008 set_remediation 재정의 --------
CREATE OR REPLACE FUNCTION set_remediation(p_account TEXT, p_status TEXT, p_note TEXT)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_actor TEXT := COALESCE(auth.jwt() ->> 'email', 'unknown');
  v_domain TEXT;
BEGIN
  IF NOT public.is_approved_user() THEN RAISE EXCEPTION '승인된 사용자만 조치할 수 있습니다'; END IF;
  IF p_status NOT IN ('open', 'remediated', 'dismissed') THEN
    RAISE EXCEPTION 'invalid status: %', p_status;
  END IF;
  UPDATE breach_findings
     SET status = p_status,
         remediation_note = p_note,
         remediated_at = CASE WHEN p_status = 'open' THEN NULL ELSE now() END,
         remediated_by = CASE WHEN p_status = 'open' THEN NULL ELSE v_actor END
   WHERE account_masked = p_account;
  SELECT domain INTO v_domain FROM breach_findings WHERE account_masked = p_account LIMIT 1;
  INSERT INTO remediation_log(account_masked, domain, status, note, actor)
  VALUES (p_account, v_domain, p_status, p_note, v_actor);
END; $$;
REVOKE ALL ON FUNCTION set_remediation(TEXT, TEXT, TEXT) FROM public;
GRANT EXECUTE ON FUNCTION set_remediation(TEXT, TEXT, TEXT) TO authenticated;

-- 9) 시드/백필: 기존 auth.users 를 app_users 로(pending), duels 를 슈퍼관리자(approved)로 -----
INSERT INTO public.app_users (id, email)
SELECT id, email FROM auth.users ON CONFLICT (id) DO NOTHING;
UPDATE public.app_users
   SET role = 'super_admin', status = 'approved', decided_at = now(), decided_by = 'system'
 WHERE email = 'duels@jbfg.com';
