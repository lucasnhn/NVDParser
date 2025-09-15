package databaseInterface

import (
	"context"
	"fmt"
	"nvd_parser/cve"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"golang.org/x/term"
)

// var pool *pgxpool.Pool

var suppliedPassword string
var suppliedUsername string = "postgres"

func InitiateConnectionPGXWithUsernameAndPassword(ctx context.Context, password string, username string) (*pgxpool.Pool, error) {
	suppliedPassword = password
	suppliedUsername = username
	return InitiateConnectionPGX(ctx)
}

// InitiateConnectionPGX prompts for a password and returns a pgx pool suitable for CopyFrom.
// Defaults: user=postgres, db=postgres, host=localhost, port=5432, sslmode=disable.
func InitiateConnectionPGX(ctx context.Context) (*pgxpool.Pool, error) {
	user := suppliedUsername
	dbname := "nvd"
	host := "localhost"
	port := 5432

	if suppliedPassword == "" {
		fmt.Printf("Enter password for Postgres user %q: ", user)
		pwBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			return nil, fmt.Errorf("read password: %w", err)
		}
		suppliedPassword = strings.TrimSpace(string(pwBytes))
	}

	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
		user, suppliedPassword, host, port, dbname)

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse dsn: %w", err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("pool create: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping db: %w", err)
	}
	return pool, nil
}

// ---------- 1) Common row builder ----------
type copyRows struct {
	cveRows [][]any
	v40Rows [][]any
	v31Rows [][]any
	v20Rows [][]any
	refRows [][]any
	ids     []string
}

const preferredSource = "nvd@nist.gov"

// queryAllCVEAndModified returns a row iterator of (cve_id, last_modified).
// Caller MUST rows.Close() after iteration.
func queryAllCVEAndModified(ctx context.Context, pool *pgxpool.Pool, cves []cve.CVE) map[string]time.Time {
	cveIDs := make([]string, len(cves))
	for i, cve := range cves {
		cveIDs[i] = cve.ID
	}

	const q = `
    SELECT cve_id, last_modified
    FROM cve
    WHERE cve_id = ANY($1)
    ORDER BY last_modified NULLS LAST, cve_id
`

	rows, err := pool.Query(ctx, q, cveIDs)
	if err != nil {
		panic(err)
	}
	defer rows.Close()

	return convertIntoMap(rows)
}

func convertIntoMap(rows pgx.Rows) map[string]time.Time {
	var resultMap map[string]time.Time = make(map[string]time.Time)
	for rows.Next() {
		var id string
		var lastModified *time.Time // handles NULL safely
		if err := rows.Scan(&id, &lastModified); err != nil {
			panic(err)
		}
		resultMap[id] = *lastModified
	}
	return resultMap
}

// Generic, in-place partition. Returns cutoff where keep(x)==true ends. Returns first indice with false keep function
func PartitionInPlace[T any](s *[]T, keep func(T) bool) int {
	a := *s
	i, j := 0, len(a)-1
	for i <= j {
		if keep(a[i]) {
			i++
			continue
		}
		if !keep(a[j]) {
			j--
			continue
		}
		a[i], a[j] = a[j], a[i]
		i++
		j--
	}
	return i
}

func testPartitioning(cves []cve.CVE, newCVES []cve.CVE, oodCVES []cve.CVE, dates map[string]time.Time) {
	var TnewCVES []cve.CVE
	var ToodCVES []cve.CVE // Out Of Date CVES

	// Recompute classification (expected sets)
	for _, cve := range cves {
		if stored, ok := dates[cve.ID]; !ok {
			TnewCVES = append(TnewCVES, cve)
		} else if lm := parseTS(cve.LastModified); lm != nil && stored.Before(*lm) {
			ToodCVES = append(ToodCVES, cve)
		}
	}

	// Helper: turn slice of CVEs into a set of IDs
	toIDSet := func(list []cve.CVE) map[string]struct{} {
		m := make(map[string]struct{}, len(list))
		for _, c := range list {
			m[c.ID] = struct{}{}
		}
		return m
	}

	// Build sets
	gotNew := toIDSet(newCVES)
	expNew := toIDSet(TnewCVES)

	gotOOD := toIDSet(oodCVES)
	expOOD := toIDSet(ToodCVES)

	// Compare sets
	isEqualNew := len(gotNew) == len(expNew)
	if isEqualNew {
		for id := range gotNew {
			if _, ok := expNew[id]; !ok {
				isEqualNew = false
				break
			}
		}
	}

	isEqualOOD := len(gotOOD) == len(expOOD)
	if isEqualOOD {
		for id := range gotOOD {
			if _, ok := expOOD[id]; !ok {
				isEqualOOD = false
				break
			}
		}
	}

	fmt.Printf("result of comparison is for newCVES: %v, for oodCVES: %v\n", isEqualNew, isEqualOOD)
}

func getPartitions(cves *[]cve.CVE, dates map[string]time.Time) (
	newCVES []cve.CVE,
	oodCVES []cve.CVE,
) {

	var cutOffNew int = PartitionInPlace(cves, func(cv cve.CVE) bool {
		_, ok := dates[cv.ID]
		return !ok
	})

	tail := (*cves)[cutOffNew:]
	tailCut := PartitionInPlace(&tail, func(cv cve.CVE) bool {
		if stored, ok := dates[cv.ID]; ok {
			if lm := parseTS(cv.LastModified); lm != nil && stored.Before(*lm) {
				return true
			}
		}
		return false
	})
	cutOffOOD := cutOffNew + tailCut
	newCVES = (*cves)[:cutOffNew]
	oodCVES = (*cves)[cutOffNew:cutOffOOD] // Out Of Date CVES
	*cves = make([]cve.CVE, 0)             // deallocating no longer needed cves
	return newCVES, oodCVES
}

func UpdateCVES(ctx context.Context, pool *pgxpool.Pool, cves *[]cve.CVE) error {
	dates := queryAllCVEAndModified(ctx, pool, *cves)
	newCVES, oodCVES := getPartitions(cves, dates)
	// testPartitioning(*cves, newCVES, oodCVES, dates)

	var err error
	if len(newCVES) > 0 {
		err = addCVEsCopy(ctx, pool, newCVES)
		if err != nil {
			return err
		}
	}
	if len(oodCVES) > 0 {
		err = replaceCVEsCopy(ctx, pool, oodCVES)
		if err != nil {
			return err
		}
	}
	if len(newCVES)+len(oodCVES) > 0 {
		fmt.Printf("database was updated on %v cves succesfully\n", len(newCVES)+len(oodCVES))
	} else {
		fmt.Println("no updates to database were found")
	}
	return nil
}

// buildCopyRows: prepares COPY rows + the id list to delete (for replace).
func buildCopyRows(cves []cve.CVE) copyRows {
	var cr copyRows
	seenRef := make(map[string]struct{}) // dedupe (cve_id,url)

	cr.cveRows = make([][]any, 0, len(cves))
	cr.ids = make([]string, 0, len(cves))

	for _, v := range cves {
		if v.ID == "" {
			continue
		}
		cr.ids = append(cr.ids, v.ID)

		desc := pickDescription(v.Descriptions)
		cr.cveRows = append(cr.cveRows, []any{
			v.ID,
			nilIfEmpty(v.CisaVulnerabilityName),
			nilIfEmpty(desc),
			parseTS(v.Published),
			parseTS(v.LastModified),
			nilIfEmpty(v.SourceIdentifier),
			nilIfEmpty(v.VulnStatus),
		})

		// references (optional; tags left NULL)
		for _, r := range v.References {
			u := strings.TrimSpace(r.URL)
			if u == "" {
				continue
			}
			key := v.ID + "\x00" + u
			if _, ok := seenRef[key]; ok {
				continue
			}
			seenRef[key] = struct{}{}
			cr.refRows = append(cr.refRows, []any{v.ID, u, nilIfEmpty(r.Source), nil})
		}

		// one preferred metric per version
		if m := pickPreferredV40(v.Metrics.CvssMetricV40); m != nil {
			d := m.CvssData
			cr.v40Rows = append(cr.v40Rows, []any{
				v.ID,
				nilIfEmpty(d.Automatable), nilIfEmpty(d.Recovery), nilIfEmpty(d.Safety),
				nilIfEmpty(d.AttackComplexity), nilIfEmpty(d.AttackRequirements), nilIfEmpty(d.AttackVector),
				nilIfEmpty(d.AvailabilityRequirement), d.BaseScore, nilIfEmpty(d.BaseSeverity),
				nilIfEmpty(d.ConfidentialityRequirement), nilIfEmpty(d.ExploitMaturity), nilIfEmpty(d.IntegrityRequirement),
				nilIfEmpty(d.ModifiedAttackComplexity), nilIfEmpty(d.ModifiedAttackRequirements), nilIfEmpty(d.ModifiedAttackVector), nilIfEmpty(d.ModifiedPrivilegesRequired),
				nilIfEmpty(d.ModifiedSubAvailabilityImpact), nilIfEmpty(d.ModifiedSubConfidentialityImpact), nilIfEmpty(d.ModifiedSubIntegrityImpact),
				nilIfEmpty(d.ModifiedUserInteraction), nilIfEmpty(d.ModifiedVulnAvailabilityImpact), nilIfEmpty(d.ModifiedVulnConfidentialityImpact), nilIfEmpty(d.ModifiedVulnIntegrityImpact),
				nilIfEmpty(d.PrivilegesRequired), nilIfEmpty(d.ProviderUrgency),
				nilIfEmpty(d.SubAvailabilityImpact), nilIfEmpty(d.SubConfidentialityImpact), nilIfEmpty(d.SubIntegrityImpact),
				nilIfEmpty(d.UserInteraction), nilIfEmpty(d.ValueDensity), nilIfEmpty(d.VectorString), nilIfEmpty(d.Version),
				nilIfEmpty(d.VulnAvailabilityImpact), nilIfEmpty(d.VulnConfidentialityImpact), nilIfEmpty(d.VulnIntegrityImpact),
				nilIfEmpty(d.VulnerabilityResponseEffort), nilIfEmpty(m.Source), nilIfEmpty(m.Type),
			})
		}
		if m := pickPreferredV31(v.Metrics.CvssMetricV31); m != nil {
			d := m.CvssData
			cr.v31Rows = append(cr.v31Rows, []any{
				v.ID,
				nilIfEmpty(d.AttackComplexity), nilIfEmpty(d.AttackVector), nilIfEmpty(d.AvailabilityImpact),
				d.BaseScore, nilIfEmpty(d.BaseSeverity),
				nilIfEmpty(d.ConfidentialityImpact), nilIfEmpty(d.IntegrityImpact),
				nilIfEmpty(d.PrivilegesRequired), nilIfEmpty(d.Scope), nilIfEmpty(d.UserInteraction),
				nilIfEmpty(d.VectorString), nilIfEmpty(d.Version),
				m.ExploitabilityScore, m.ImpactScore, nilIfEmpty(m.Source), nilIfEmpty(m.Type),
			})
		}
		if m := pickPreferredV20(v.Metrics.CvssMetricV2); m != nil {
			d := m.CvssData
			cr.v20Rows = append(cr.v20Rows, []any{
				v.ID,
				m.AcInsufInfo, nilIfEmpty(m.BaseSeverity),
				nilIfEmpty(d.AccessComplexity), nilIfEmpty(d.AccessVector), nilIfEmpty(d.Authentication), nilIfEmpty(d.AvailabilityImpact),
				d.BaseScore, nilIfEmpty(d.ConfidentialityImpact), nilIfEmpty(d.IntegrityImpact),
				nilIfEmpty(d.VectorString), nilIfEmpty(d.Version),
				m.ExploitabilityScore, m.ImpactScore,
				m.ObtainAllPrivilege, m.ObtainOtherPrivilege, m.ObtainUserPrivilege,
				nilIfEmpty(m.Source), nilIfEmpty(m.Type), m.UserInteractionRequired,
			})
		}
	}
	return cr
}

/* =========================
   Replace (delete + insert)
   ========================= */

// replaceCVEsCopy deletes those CVEs (cascades metrics/references) then re-inserts fresh rows.
// ---------- 2) Common inserter used by both add & replace ----------
func insertBundleTx(ctx context.Context, tx pgx.Tx, cr copyRows) error {
	// cve
	if len(cr.cveRows) > 0 {
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"cve"},
			[]string{"cve_id", "title", "description", "published", "last_modified", "source_identifier", "vuln_status"},
			pgx.CopyFromRows(cr.cveRows)); err != nil {
			return err
		}
	}
	// references
	if len(cr.refRows) > 0 {
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"cve_reference"},
			[]string{"cve_id", "url", "source", "tags"},
			pgx.CopyFromRows(cr.refRows)); err != nil {
			return err
		}
	}
	// metrics v40
	if len(cr.v40Rows) > 0 {
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"cvss_v40"},
			[]string{
				"cve_id", "automatable", "recovery", "safety",
				"attack_complexity", "attack_requirements", "attack_vector",
				"availability_requirement", "base_score", "base_severity",
				"confidentiality_requirement", "exploit_maturity", "integrity_requirement",
				"modified_attack_complexity", "modified_attack_requirements", "modified_attack_vector", "modified_privileges_required",
				"modified_sub_availability_impact", "modified_sub_confidentiality_impact", "modified_sub_integrity_impact",
				"modified_user_interaction", "modified_vuln_availability_impact", "modified_vuln_confidentiality_impact", "modified_vuln_integrity_impact",
				"privileges_required", "provider_urgency",
				"sub_availability_impact", "sub_confidentiality_impact", "sub_integrity_impact",
				"user_interaction", "value_density", "vector_string", "version",
				"vuln_availability_impact", "vuln_confidentiality_impact", "vuln_integrity_impact",
				"vulnerability_response_effort", "source", "type",
			},
			pgx.CopyFromRows(cr.v40Rows)); err != nil {
			return err
		}
	}
	// metrics v31
	if len(cr.v31Rows) > 0 {
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"cvss_v31"},
			[]string{
				"cve_id", "attack_complexity", "attack_vector", "availability_impact",
				"base_score", "base_severity",
				"confidentiality_impact", "integrity_impact",
				"privileges_required", "scope", "user_interaction",
				"vector_string", "version",
				"exploitability_score", "impact_score",
				"source", "type",
			},
			pgx.CopyFromRows(cr.v31Rows)); err != nil {
			return err
		}
	}
	// metrics v20
	if len(cr.v20Rows) > 0 {
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"cvss_v20"},
			[]string{
				"cve_id", "ac_insuf_info", "base_severity",
				"access_complexity", "access_vector", "authentication", "availability_impact",
				"base_score", "confidentiality_impact", "integrity_impact",
				"vector_string", "version",
				"exploitability_score", "impact_score",
				"obtain_all_privilege", "obtain_other_privilege", "obtain_user_privilege",
				"source", "type", "user_interaction_required",
			},
			pgx.CopyFromRows(cr.v20Rows)); err != nil {
			return err
		}
	}
	return nil
}

// ---------- 3) Add: tx + insert ----------
func addCVEsCopy(ctx context.Context, pool *pgxpool.Pool, cves []cve.CVE) error {
	cr := buildCopyRows(cves)
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		return insertBundleTx(ctx, tx, cr)
	})
}

// ---------- 4) Replace: tx + delete + insert ----------
func replaceCVEsCopy(ctx context.Context, pool *pgxpool.Pool, cves []cve.CVE) error {
	cr := buildCopyRows(cves)
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if len(cr.ids) > 0 {
			if _, err := tx.Exec(ctx, `DELETE FROM cve WHERE cve_id = ANY($1)`, cr.ids); err != nil {
				return err
			}
		}
		return insertBundleTx(ctx, tx, cr)
	})
}
func pickDescription(list []cve.LangValue) string {
	var first string
	for _, d := range list {
		val := strings.TrimSpace(d.Value)
		if first == "" && val != "" {
			first = val
		}
		if strings.EqualFold(d.Lang, "en") && val != "" {
			return val // returns the english description
		}
	}
	return first // returns the first language found since english is not present
}

func nilIfEmpty(s string) any {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return s
}

func pickPreferredV40(list []cve.CvssV40) *cve.CvssV40 {
	for _, m := range list {
		if strings.EqualFold(m.Source, preferredSource) {
			return &m
		}
	}
	if len(list) > 0 {
		return &list[0]
	}
	return nil
}

func pickPreferredV31(list []cve.CvssV3x) *cve.CvssV3x {
	for _, m := range list {
		if strings.EqualFold(m.Source, preferredSource) {
			return &m
		}
	}
	if len(list) > 0 {
		return &list[0]
	}
	return nil
}

func pickPreferredV20(list []cve.CvssV2) *cve.CvssV2 {
	for _, m := range list {
		if strings.EqualFold(m.Source, preferredSource) {
			return &m
		}
	}
	if len(list) > 0 {
		return &list[0]
	}
	return nil
}

// parseTS converts common ISO-8601 / RFC3339-like strings to *time.Time (UTC).
// Returns nil if empty or if parsing fails.
func parseTS(s string) *time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	layouts := []string{
		time.RFC3339Nano,                // 2025-09-08T12:34:56.123456789Z
		time.RFC3339,                    // 2025-09-08T12:34:56Z
		"2006-01-02T15:04:05.000Z07:00", // 2025-09-08T12:34:56.140+00:00
		"2006-01-02T15:04:05Z07:00",     // 2025-09-08T12:34:56+00:00
		"2006-01-02T15:04:05.000",       // 2023-11-28T00:15:07.140  (no TZ)
		"2006-01-02T15:04:05",           // 2023-11-28T00:15:07     (no TZ)
		"2006-01-02 15:04:05.000",       // 2023-11-28 00:15:07.140 (space, no TZ)
		"2006-01-02 15:04:05",           // 2023-11-28 00:15:07     (space, no TZ)
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, s); err == nil {
			tt := t.UTC()
			return &tt
		}
	}
	// As a last try, assume "no-TZ" milliseconds in UTC explicitly
	if t, err := time.ParseInLocation("2006-01-02T15:04:05.000", s, time.UTC); err == nil {
		tt := t.UTC()
		return &tt
	}
	return nil
}
