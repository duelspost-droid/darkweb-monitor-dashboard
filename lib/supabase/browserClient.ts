// 브라우저(클라이언트)용 Supabase 클라이언트.
// anon 키는 공개돼도 되지만, 데이터는 RLS(로그인 필요)로 보호된다.
import { createClient } from "@supabase/supabase-js";

const url = process.env.NEXT_PUBLIC_SUPABASE_URL ?? "";
const anon = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY ?? "";

export const supabase = createClient(url, anon, {
  auth: { persistSession: true, autoRefreshToken: true },
});

export const supabaseConfigured = Boolean(url && anon);

// 고정 관리자 계정 이메일. 설정 시 로그인 폼은 비밀번호만 받고 이 계정으로 인증한다.
// (Supabase Auth 는 식별자가 필수라 이메일은 클라이언트에 노출되지만, 게이트는 비밀번호다.)
export const adminEmail = (process.env.NEXT_PUBLIC_ADMIN_EMAIL ?? "").trim();
