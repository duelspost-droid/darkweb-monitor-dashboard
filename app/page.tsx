// 관리자 인증(Supabase Auth) 후에만 데이터를 조회·표시하는 비공개 대시보드.
// 정적 빌드에는 실데이터를 굽지 않는다(공개 repo/Pages 에 데이터 미노출).
import DashboardClient from "./DashboardClient";

export default function SecurityPage() {
  return <DashboardClient />;
}
