-- 008: 조치(remediation) 상태 + 조치내역(감사 로그).
--  - breach_findings 에 status/메모/조치자/시각 추가 (계정 그룹 단위로 관리)
--  - remediation_log: 모든 상태 변경 이력(append-only, finding 삭제돼도 보존)
--  - set_remediation(): 인증 사용자만 호출. 상태 변경 + 로그 적재를 원자적으로.
--  ※ 자정 재스캔(Edge Function service_role upsert)은 status 컬럼을 payload에 안 보내므로
--    merge-duplicates 가 기존 status 를 보존한다(덮어쓰지 않음).

-- 조치 상태 컬럼 (open=미조치 | remediated=조치완료 | dismissed=이상없음)
ALTER TABLE breach_findings ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'open';
ALTER TABLE breach_findings ADD COLUMN IF NOT EXISTS remediation_note TEXT;
ALTER TABLE breach_findings ADD COLUMN IF NOT EXISTS remediated_at TIMESTAMPTZ;
ALTER TABLE breach_findings ADD COLUMN IF NOT EXISTS remediated_by TEXT;

-- 조치 내역(감사 로그)
CREATE TABLE IF NOT EXISTS remediation_log (
  id            BIGSERIAL PRIMARY KEY,
  account_masked TEXT,
  domain        TEXT,
  status        TEXT,        -- 변경된 상태
  note          TEXT,        -- 조치 의견/메모
  actor         TEXT,        -- 수행 관리자(이메일)
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_remediation_log_account ON remediation_log (account_masked);
CREATE INDEX IF NOT EXISTS idx_remediation_log_created ON remediation_log (created_at DESC);

ALTER TABLE remediation_log ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS remediation_log_read ON remediation_log;
CREATE POLICY remediation_log_read ON remediation_log FOR SELECT TO authenticated USING (true);
DROP POLICY IF EXISTS remediation_log_write ON remediation_log;
CREATE POLICY remediation_log_write ON remediation_log FOR INSERT TO authenticated WITH CHECK (true);

-- 계정(그룹) 단위 상태 변경 + 로그 (인증 사용자만)
CREATE OR REPLACE FUNCTION set_remediation(p_account TEXT, p_status TEXT, p_note TEXT)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_actor TEXT := COALESCE(auth.jwt() ->> 'email', 'unknown');
  v_domain TEXT;
BEGIN
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
END;
$$;
REVOKE ALL ON FUNCTION set_remediation(TEXT, TEXT, TEXT) FROM public;
GRANT EXECUTE ON FUNCTION set_remediation(TEXT, TEXT, TEXT) TO authenticated;
