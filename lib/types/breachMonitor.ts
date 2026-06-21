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
}
