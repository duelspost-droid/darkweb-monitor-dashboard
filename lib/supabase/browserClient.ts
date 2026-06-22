// 브라우저(클라이언트)용 Supabase 클라이언트.
// anon 키는 공개돼도 되지만, 데이터는 RLS(로그인 필요)로 보호된다.
import { createClient } from "@supabase/supabase-js";

const url = process.env.NEXT_PUBLIC_SUPABASE_URL ?? "";
const anon = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY ?? "";

export const supabase = createClient(url, anon, {
  auth: { persistSession: true, autoRefreshToken: true },
});

export const supabaseConfigured = Boolean(url && anon);
