// Edge Function: admin-users
// 승인 관리자(admin_allowlist) 전용 — Supabase Auth 계정 생성 / 비밀번호 지정·초기화 / 삭제.
// admin_allowlist 는 "데이터 접근 권한"만 부여하고 실제 로그인 계정은 별도 필요했다(011/012 주석 참고).
// 이 함수가 그 빈틈을 메운다: 관리자 페이지에서 이메일+비밀번호로 실제 Auth 계정을 직접 만들고
// 비밀번호를 지정/초기화할 수 있게 한다. admin_allowlist 자체(허용 목록 추가/삭제)는 기존
// AdminAccountsPanel(대시보드 UI)이 authenticated+is_admin() RLS로 이미 직접 처리한다 — 건드리지 않음.
//
//   action: "create_user"  → 이메일+비밀번호로 신규 Auth 계정 생성(이메일 인증 완료 처리)
//           "set_password" → 이메일로 기존 계정을 찾아 비밀번호 재설정(초기화/지정)
//           "delete_user"  → 이메일로 기존 계정을 찾아 Auth 계정 삭제
//
// 보안: verify_jwt=false 로 두고 코드에서 직접 검증한다.
//   1) 호출자의 Bearer JWT 로 getUser → 신원 확인
//   2) service_role 로 admin_allowlist 에 호출자 이메일이 있는지 확인(is_admin() 과 동일 기준)
//   3) 통과해야만 Admin API 실행. service_role 키는 응답에 절대 포함하지 않는다.
// service_role/anon/URL 은 Supabase 가 Edge 런타임에 자동 주입하는 시크릿을 사용(값 하드코딩 없음).

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "";
const SERVICE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";
const ANON_KEY = Deno.env.get("SUPABASE_ANON_KEY") ?? "";

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...CORS, "Content-Type": "application/json" },
  });
}

function validPassword(pw: unknown): pw is string {
  return typeof pw === "string" && pw.length >= 8;
}
function validEmail(e: unknown): e is string {
  return typeof e === "string" && /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e);
}

// gotrue admin API 에 이메일 직접 조회가 없어 목록에서 찾는다(관리자 수가 적어 충분).
async function findUserByEmail(admin: ReturnType<typeof createClient>, email: string) {
  const { data, error } = await admin.auth.admin.listUsers({ page: 1, perPage: 1000 });
  if (error) throw error;
  return data.users.find((u) => (u.email ?? "").toLowerCase() === email.toLowerCase()) ?? null;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });
  if (req.method !== "POST") return json(405, { error: "method not allowed" });

  const jwt = (req.headers.get("Authorization") ?? "").replace(/^Bearer\s+/i, "").trim();
  if (!jwt) return json(401, { error: "인증 토큰이 없습니다" });

  const asUser = createClient(SUPABASE_URL, ANON_KEY, {
    global: { headers: { Authorization: `Bearer ${jwt}` } },
  });
  const { data: userData, error: userErr } = await asUser.auth.getUser();
  const caller = userData?.user;
  if (userErr || !caller?.email) return json(401, { error: "유효하지 않은 세션입니다" });

  const admin = createClient(SUPABASE_URL, SERVICE_KEY, { auth: { persistSession: false } });

  // 승인 관리자 확인 — admin_allowlist 기준(is_admin() 과 동일한 기준, service_role 로 직접 조회).
  const { data: allow } = await admin
    .from("admin_allowlist")
    .select("email")
    .eq("email", caller.email)
    .maybeSingle();
  if (!allow) return json(403, { error: "승인 관리자만 사용할 수 있습니다" });

  let body: Record<string, unknown>;
  try {
    body = await req.json();
  } catch {
    return json(400, { error: "잘못된 요청 본문" });
  }
  const action = String(body.action ?? "");

  try {
    if (action === "create_user") {
      const email = body.email;
      const password = body.password;
      if (!validEmail(email)) return json(400, { error: "이메일 형식이 올바르지 않습니다" });
      if (!validPassword(password)) return json(400, { error: "비밀번호는 8자 이상이어야 합니다" });

      const existing = await findUserByEmail(admin, email);
      if (existing) return json(400, { error: "이미 계정이 있습니다. '비밀번호 재설정'을 사용하세요." });

      const { data: created, error: cErr } = await admin.auth.admin.createUser({
        email,
        password,
        email_confirm: true,
      });
      if (cErr || !created?.user) return json(400, { error: `생성 실패: ${cErr?.message ?? "unknown"}` });
      return json(200, { ok: true, id: created.user.id, email });
    }

    if (action === "set_password") {
      const email = body.email;
      const password = body.password;
      if (!validEmail(email)) return json(400, { error: "이메일 형식이 올바르지 않습니다" });
      if (!validPassword(password)) return json(400, { error: "비밀번호는 8자 이상이어야 합니다" });
      if (email.toLowerCase() === caller.email.toLowerCase()) {
        return json(400, { error: "본인 비밀번호는 '비밀번호 변경'에서 바꾸세요" });
      }

      const found = await findUserByEmail(admin, email);
      if (!found) return json(404, { error: "해당 이메일의 계정이 없습니다. 먼저 계정을 생성하세요." });

      const { error: pErr } = await admin.auth.admin.updateUserById(found.id, { password });
      if (pErr) return json(400, { error: `설정 실패: ${pErr.message}` });
      return json(200, { ok: true });
    }

    if (action === "delete_user") {
      const email = body.email;
      if (!validEmail(email)) return json(400, { error: "이메일 형식이 올바르지 않습니다" });
      if (email.toLowerCase() === caller.email.toLowerCase()) {
        return json(400, { error: "본인 계정은 삭제할 수 없습니다" });
      }

      const found = await findUserByEmail(admin, email);
      if (!found) return json(404, { error: "해당 이메일의 계정이 없습니다" });

      const { error: dErr } = await admin.auth.admin.deleteUser(found.id);
      if (dErr) return json(400, { error: `삭제 실패: ${dErr.message}` });
      return json(200, { ok: true });
    }

    return json(400, { error: `알 수 없는 action: ${action}` });
  } catch (e) {
    return json(500, { error: `서버 오류: ${(e as Error).message}` });
  }
});
