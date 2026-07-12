// 다크웹/유출 인텔리전스 모니터링 도메인 타입.
// 개인정보 제약: 계정은 항상 마스킹된 형태(accountMasked)로만 보관·표시한다.
// 평문 비밀번호·전체 이메일·기타 식별자는 저장하지 않는다.

export type BreachSeverity = "critical" | "high" | "medium" | "low";

export type BreachScanStatus = "ok" | "no_api_key" | "error";

export interface BreachFinding {
  id: string;
  // 마스킹된 계정 (예: "jo***@jbfg.com"). 전체 로컬파트는 저장하지 않는다.
  accountMasked: string;
  domain: string;
  breachName: string;
  breachTitle: string;
  // YYYY-MM-DD (유출 사건 발생/공개 일자)
  breachDate: string;
  // 노출된 데이터 분류 (예: "이메일", "비밀번호"). 값 자체는 저장하지 않는다.
  dataClasses: string[];
  severity: BreachSeverity;
  // 직전 스캔 대비 새로 발견된 항목 여부
  isNew: boolean;
  discoveredAt: string;
  // 수집 출처 (예: "XposedOrNot", "Have I Been Pwned", "공개 노출 (GitHub)")
  source: string;
  // 참고 링크 (예: GitHub 노출 파일 URL) — 있으면 표시
  referenceUrl?: string;
  // 개인정보 노출 위치 — 카테고리별 라인번호(값·문맥 미저장, 위치만). referenceUrl#L<line> 딥링크로 표시.
  piiLocations?: { category: string; lines: number[] }[];
  // 조치 상태 (open=미조치 | remediated=조치완료 | dismissed=이상없음) + 조치 기록
  status?: string;
  remediationNote?: string;
  remediatedBy?: string;
  remediatedAt?: string;
}

// 다크웹 인포스틸러(악성코드) 감염 — 도메인 전수 집계 (Hudson Rock Cavalier).
export interface InfostealerFinding {
  domain: string;
  source: string; // "Hudson Rock Cavalier"
  total: number; // 도메인 관련 감염 총계
  employees: number; // 임직원(도메인 메일) 감염
  users: number; // 사용자/고객 감염
  thirdParties: number; // 서드파티 감염
  affectedUrls: { url: string; type: string; occurrence: number }[]; // 영향받은 URL Top
  firstSeenAt?: string; // 최초 탐지(우리 스캔에 처음 잡힌 시점) — 타임라인
  scannedAt: string;
}

// 인포스틸러 감염 호스트(피해자) 상세 — Hudson Rock Cavalier search-by-email.
// 민감정보(비번/IP)는 Hudson Rock 이 부분 마스킹한 값만 보관. 관리자 인증 후에만 조회.
export interface InfostealerHost {
  accountMasked: string;
  domain: string;
  computerName: string | null; // 감염 PC 이름
  operatingSystem: string | null;
  ip: string | null; // 부분 마스킹 IP
  dateCompromised: string | null; // YYYY-MM-DD
  stealerFamily: string | null; // 스틸러 종류
  malwarePath: string | null; // 악성코드 실행 경로
  antiviruses: string[]; // 감염 당시 설치 백신
  totalCorporateServices: number; // 탈취 사내 서비스 수
  totalUserServices: number; // 탈취 개인 서비스 수
  topPasswords: string[]; // 부분 마스킹 비번 샘플(평문 아님)
  topLogins: string[]; // 부분 마스킹 로그인 샘플
  firstSeenAt?: string; // 최초 탐지 — 타임라인
  scannedAt: string;
}

// 수집 출처 기록 (provenance) — 어떤 소스에서, 언제, 몇 건 수집했는지.
export interface SourceRecord {
  name: string; // "XposedOrNot (계정별 유출 조회)"
  kind: "breach" | "infostealer"; // 데이터 종류
  endpoint: string; // 호출한 API 엔드포인트
  count: number; // 수집 건수
  scannedAt: string;
}

export interface BreachScanSummary {
  total: number;
  newCount: number;
  bySeverity: Record<BreachSeverity, number>;
  byDomain: { domain: string; count: number }[];
}

export interface BreachScanHistoryPoint {
  scannedAt: string;
  total: number;
  newCount: number;
}

export interface BreachScan {
  generatedAt: string;
  // 데이터 출처 설명 (예: "Have I Been Pwned (도메인 검색 API)")
  source: string;
  status: BreachScanStatus;
  // API 키 미설정 등으로 실데이터 대신 데모 데이터를 표시 중인지 여부
  isDemo: boolean;
  domains: string[];
  findings: BreachFinding[];
  summary: BreachScanSummary;
  history: BreachScanHistoryPoint[];
  note?: string;
  // 다크웹 인포스틸러 감염 (도메인 전수, Hudson Rock Cavalier)
  infostealer?: InfostealerFinding[];
  // 인포스틸러 감염 호스트(피해자) 상세 — 관리자 인증 후에만 채워짐
  infostealerHosts?: InfostealerHost[];
  // 수집 출처 기록 (provenance)
  sources?: SourceRecord[];
}
