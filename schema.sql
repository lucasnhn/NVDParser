CREATE TABLE IF NOT EXISTS cve (
  cve_id            text PRIMARY KEY,     -- e.g., CVE-2024-12345
  title             text,                 -- CisaVulnerabilityName
  description       text,                 -- pick 'en' value during ingest
  published         timestamptz,
  last_modified     timestamptz,
  source_identifier text,
  vuln_status       text,
  created_at        timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_cve_published     ON cve (published);
CREATE INDEX IF NOT EXISTS idx_cve_last_modified ON cve (last_modified);

CREATE TABLE IF NOT EXISTS cve_reference (
  id      bigserial PRIMARY KEY,
  cve_id  text NOT NULL REFERENCES cve(cve_id) ON DELETE CASCADE,
  url     text NOT NULL,
  source  text,
  tags    text[]
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_cve_reference_cve_url ON cve_reference (cve_id, url);
CREATE INDEX IF NOT EXISTS idx_cve_reference_tags ON cve_reference USING gin (tags);

-- =========================
-- CVSS v4.0 (full, criticality-relevant fields)
-- =========================
CREATE TABLE IF NOT EXISTS cvss_v40 (
  id                                bigserial PRIMARY KEY,
  cve_id                            text NOT NULL REFERENCES cve(cve_id) ON DELETE CASCADE,

  -- cvssData (all the parts you provided)
  automatable                       text,
  recovery                          text,
  safety                            text,
  attack_complexity                 text,
  attack_requirements               text,
  attack_vector                     text,
  availability_requirement          text,
  base_score                        numeric(3,1) CHECK (base_score >= 0 AND base_score <= 10),
  base_severity                     text,
  confidentiality_requirement       text,
  exploit_maturity                  text,
  integrity_requirement             text,
  modified_attack_complexity        text,
  modified_attack_requirements      text,
  modified_attack_vector            text,
  modified_privileges_required      text,
  modified_sub_availability_impact  text,
  modified_sub_confidentiality_impact text,
  modified_sub_integrity_impact     text,
  modified_user_interaction         text,
  modified_vuln_availability_impact text,
  modified_vuln_confidentiality_impact text,
  modified_vuln_integrity_impact    text,
  privileges_required               text,
  provider_urgency                  text,
  sub_availability_impact           text,
  sub_confidentiality_impact        text,
  sub_integrity_impact              text,
  user_interaction                  text,
  value_density                     text,
  vector_string                     text,
  version                           text,  -- e.g., '4.0'
  vuln_availability_impact          text,
  vuln_confidentiality_impact       text,
  vuln_integrity_impact             text,
  vulnerability_response_effort     text,

  -- record-level
  source                            text,
  type                              text,

  created_at                        timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_cvss_v40_cve_src_type_vec_ver
  ON cvss_v40 (cve_id, source, type, vector_string, version);
CREATE INDEX IF NOT EXISTS idx_cvss_v40_score ON cvss_v40 (base_score);

-- =========================
-- CVSS v3.1 (full base metrics + scores)
-- =========================
CREATE TABLE IF NOT EXISTS cvss_v31 (
  id                     bigserial PRIMARY KEY,
  cve_id                 text NOT NULL REFERENCES cve(cve_id) ON DELETE CASCADE,

  -- cvssData (v3.1)
  attack_complexity      text,
  attack_vector          text,
  availability_impact    text,
  base_score             numeric(3,1) CHECK (base_score >= 0 AND base_score <= 10),
  base_severity          text,
  confidentiality_impact text,
  integrity_impact       text,
  privileges_required    text,
  scope                  text,
  user_interaction       text,
  vector_string          text,
  version                text,  -- '3.1'

  -- record-level
  exploitability_score   double precision,
  impact_score           double precision,
  source                 text,
  type                   text,

  created_at             timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_cvss_v31_cve_src_type_vec_ver
  ON cvss_v31 (cve_id, source, type, vector_string, version);
CREATE INDEX IF NOT EXISTS idx_cvss_v31_score ON cvss_v31 (base_score);

-- =========================
-- CVSS v2.0 (full base metrics + scores/flags)
-- =========================
CREATE TABLE IF NOT EXISTS cvss_v20 (
  id                         bigserial PRIMARY KEY,
  cve_id                     text NOT NULL REFERENCES cve(cve_id) ON DELETE CASCADE,

  -- flags/metadata
  ac_insuf_info              boolean,
  base_severity              text,

  -- cvssData (v2)
  access_complexity          text,
  access_vector              text,
  authentication             text,
  availability_impact        text,
  base_score                 numeric(3,1) CHECK (base_score >= 0 AND base_score <= 10),
  confidentiality_impact     text,
  integrity_impact           text,
  vector_string              text,
  version                    text,  -- '2.0'

  -- record-level
  exploitability_score       double precision,
  impact_score               double precision,
  obtain_all_privilege       boolean,
  obtain_other_privilege     boolean,
  obtain_user_privilege      boolean,
  source                     text,
  type                       text,
  user_interaction_required  boolean,

  created_at                 timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_cvss_v20_cve_src_type_vec_ver
  ON cvss_v20 (cve_id, source, type, vector_string, version);
CREATE INDEX IF NOT EXISTS idx_cvss_v20_score ON cvss_v20 (base_score);



CREATE TABLE IF NOT EXISTS cve_configuration (
  id         bigserial PRIMARY KEY,
  cve_id     text NOT NULL REFERENCES cve(cve_id) ON DELETE CASCADE,
  data       JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cve_configuration_cve ON cve_configuration (cve_id);


CREATE OR REPLACE VIEW cve_best_cvss_full AS
SELECT
  -- ===== CVE fields =====
  c.cve_id,
  c.title,
  c.description,
  c.published,
  c.last_modified,
  c.vuln_status,

  -- ===== Core CVSS outputs =====
  COALESCE(v40.base_score, v31.base_score, v20.base_score)          AS base_score,
  COALESCE(v40.base_severity, v31.base_severity, v20.base_severity) AS base_severity,
  COALESCE(v40.vector_string, v31.vector_string, v20.vector_string) AS vector_string,

  -- identify whose score you stored (you control upstream)
  COALESCE(v40.source, v31.source, v20.source) AS metric_source,
  COALESCE(v40.type,   v31.type,   v20.type)   AS metric_type,

  -- ===== Normalized base metrics =====
  COALESCE(v40.attack_vector,     v31.attack_vector,     v20.access_vector)     AS attack_vector,
  COALESCE(v40.attack_complexity, v31.attack_complexity, v20.access_complexity) AS attack_complexity,
  COALESCE(v40.privileges_required, v31.privileges_required) AS privileges_required,
  COALESCE(
    v40.user_interaction,
    v31.user_interaction,
    CASE v20.user_interaction_required
      WHEN TRUE  THEN 'REQUIRED'
      WHEN FALSE THEN 'NONE'
      ELSE NULL
    END
  ) AS user_interaction,
  v31.scope AS scope,
  COALESCE(v40.vuln_availability_impact,    v31.availability_impact,    v20.availability_impact)    AS availability_impact,
  COALESCE(v40.vuln_confidentiality_impact, v31.confidentiality_impact, v20.confidentiality_impact) AS confidentiality_impact,
  COALESCE(v40.vuln_integrity_impact,       v31.integrity_impact,       v20.integrity_impact)       AS integrity_impact,
  COALESCE(v31.exploitability_score, v20.exploitability_score) AS exploitability_score,
  COALESCE(v31.impact_score,         v20.impact_score)         AS impact_score,

  -- ===== Additional v4.0 knobs =====
  v40.automatable,
  v40.recovery,
  v40.safety,
  v40.attack_requirements,
  v40.availability_requirement,
  v40.confidentiality_requirement,
  v40.integrity_requirement,
  v40.exploit_maturity,
  v40.modified_attack_complexity,
  v40.modified_attack_requirements,
  v40.modified_attack_vector,
  v40.modified_privileges_required,
  v40.modified_sub_availability_impact,
  v40.modified_sub_confidentiality_impact,
  v40.modified_sub_integrity_impact,
  v40.modified_user_interaction,
  v40.modified_vuln_availability_impact,
  v40.modified_vuln_confidentiality_impact,
  v40.modified_vuln_integrity_impact,
  v40.provider_urgency,
  v40.sub_availability_impact,
  v40.sub_confidentiality_impact,
  v40.sub_integrity_impact,
  v40.value_density,
  v40.vulnerability_response_effort,

  -- ===== v2-only =====
  v20.authentication,
  v20.ac_insuf_info,
  v20.obtain_all_privilege,
  v20.obtain_other_privilege,
  v20.obtain_user_privilege,

  -- ===== Aggregated configuration list (one extra column) =====
  cfg.configuration_list

FROM cve c
LEFT JOIN cvss_v40 v40 USING (cve_id)
LEFT JOIN cvss_v31 v31 USING (cve_id)
LEFT JOIN cvss_v20 v20 USING (cve_id)
LEFT JOIN LATERAL (
  SELECT array_agg(DISTINCT cc.data ORDER BY cc.data) AS configuration_list
  FROM cve_configuration cc
  WHERE cc.cve_id = c.cve_id
) cfg ON true;
