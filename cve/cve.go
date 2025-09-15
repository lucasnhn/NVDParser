// Go structs for NVD JSON 2.0 Feeds
// Fields use precise json tags and collapse array indices via slices.
// Numbers that are scores are float64; counts/indices are ints.
// Dates/timestamps remain strings.

package cve

// Root is the top-level document.
type Root struct {
	Format          string          `json:"format"`
	ResultsPerPage  int             `json:"resultsPerPage"`
	StartIndex      int             `json:"startIndex"`
	Timestamp       string          `json:"timestamp"`
	TotalResults    int             `json:"totalResults"`
	Version         string          `json:"version"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// Vulnerability wraps a CVE entry.
type Vulnerability struct {
	CVE CVE `json:"cve"`
}

// CVE contains the CVE core fields.
type CVE struct {
	CisaActionDue         string          `json:"cisaActionDue"`
	CisaExploitAdd        string          `json:"cisaExploitAdd"`
	CisaRequiredAction    string          `json:"cisaRequiredAction"`
	CisaVulnerabilityName string          `json:"cisaVulnerabilityName"`
	Configurations        []Configuration `json:"configurations"`
	CveTags               []CveTag        `json:"cveTags"`
	Descriptions          []LangValue     `json:"descriptions"`
	ID                    string          `json:"id"`
	LastModified          string          `json:"lastModified"`
	Metrics               Metrics         `json:"metrics"`
	Published             string          `json:"published"`
	References            []Reference     `json:"references"`
	SourceIdentifier      string          `json:"sourceIdentifier"`
	VulnStatus            string          `json:"vulnStatus"`
	Weaknesses            []Weakness      `json:"weaknesses"`
}

// Configuration represents a top-level configuration block.
type Configuration struct {
	Nodes    []Node `json:"nodes"`
	Operator string `json:"operator"`
}

// Node represents a configuration node with CPE matches and/or children.
type Node struct {
	CPEMatch []CPEMatch `json:"cpeMatch"`
	Negate   bool       `json:"negate"`
	Operator string     `json:"operator"`
}

// CPEMatch represents a single CPE match entry within a node.
type CPEMatch struct {
	Criteria              string `json:"criteria"`
	MatchCriteriaID       string `json:"matchCriteriaId"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	Vulnerable            bool   `json:"vulnerable"`
}

// CveTag groups tags with their source identifier.
type CveTag struct {
	SourceIdentifier string   `json:"sourceIdentifier"`
	Tags             []string `json:"tags"`
}

// LangValue is a {lang, value} pair used in descriptions and weakness descriptions.
type LangValue struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

// Metrics holds various CVSS metric versions.
type Metrics struct {
	CvssMetricV2  []CvssV2  `json:"cvssMetricV2"`
	CvssMetricV30 []CvssV3x `json:"cvssMetricV30"`
	CvssMetricV31 []CvssV3x `json:"cvssMetricV31"`
	CvssMetricV40 []CvssV40 `json:"cvssMetricV40"`
}

// CvssV2 is a CVSS v2 metric record.
type CvssV2 struct {
	AcInsufInfo             bool       `json:"acInsufInfo"`
	BaseSeverity            string     `json:"baseSeverity"`
	CvssData                CvssV2Data `json:"cvssData"`
	ExploitabilityScore     float64    `json:"exploitabilityScore"`
	ImpactScore             float64    `json:"impactScore"`
	ObtainAllPrivilege      bool       `json:"obtainAllPrivilege"`
	ObtainOtherPrivilege    bool       `json:"obtainOtherPrivilege"`
	ObtainUserPrivilege     bool       `json:"obtainUserPrivilege"`
	Source                  string     `json:"source"`
	Type                    string     `json:"type"`
	UserInteractionRequired bool       `json:"userInteractionRequired"`
}

// CvssV2Data contains the v2 vector details.
type CvssV2Data struct {
	AccessComplexity      string  `json:"accessComplexity"`
	AccessVector          string  `json:"accessVector"`
	Authentication        string  `json:"authentication"`
	AvailabilityImpact    string  `json:"availabilityImpact"`
	BaseScore             float64 `json:"baseScore"`
	ConfidentialityImpact string  `json:"confidentialityImpact"`
	IntegrityImpact       string  `json:"integrityImpact"`
	VectorString          string  `json:"vectorString"`
	Version               string  `json:"version"`
}

// CvssV3x covers both v3.0 and v3.1 metric records (same shape).
type CvssV3x struct {
	CvssData            CvssV3xData `json:"cvssData"`
	ExploitabilityScore float64     `json:"exploitabilityScore"`
	ImpactScore         float64     `json:"impactScore"`
	Source              string      `json:"source"`
	Type                string      `json:"type"`
}

// CvssV3xData holds the CVSS v3.0/3.1 vector fields.
type CvssV3xData struct {
	AttackComplexity      string  `json:"attackComplexity"`
	AttackVector          string  `json:"attackVector"`
	AvailabilityImpact    string  `json:"availabilityImpact"`
	BaseScore             float64 `json:"baseScore"`
	BaseSeverity          string  `json:"baseSeverity"`
	ConfidentialityImpact string  `json:"confidentialityImpact"`
	IntegrityImpact       string  `json:"integrityImpact"`
	PrivilegesRequired    string  `json:"privilegesRequired"`
	Scope                 string  `json:"scope"`
	UserInteraction       string  `json:"userInteraction"`
	VectorString          string  `json:"vectorString"`
	Version               string  `json:"version"`
}

// CvssV40 is a CVSS v4.0 metric record (expanded attributes).
type CvssV40 struct {
	CvssData CvssV40Data `json:"cvssData"`
	Source   string      `json:"source"`
	Type     string      `json:"type"`
}

// CvssV40Data contains CVSS v4.0 fields as presented in the schema.
type CvssV40Data struct {
	Automatable                       string  `json:"Automatable"`
	Recovery                          string  `json:"Recovery"`
	Safety                            string  `json:"Safety"`
	AttackComplexity                  string  `json:"attackComplexity"`
	AttackRequirements                string  `json:"attackRequirements"`
	AttackVector                      string  `json:"attackVector"`
	AvailabilityRequirement           string  `json:"availabilityRequirement"`
	BaseScore                         float64 `json:"baseScore"`
	BaseSeverity                      string  `json:"baseSeverity"`
	ConfidentialityRequirement        string  `json:"confidentialityRequirement"`
	ExploitMaturity                   string  `json:"exploitMaturity"`
	IntegrityRequirement              string  `json:"integrityRequirement"`
	ModifiedAttackComplexity          string  `json:"modifiedAttackComplexity"`
	ModifiedAttackRequirements        string  `json:"modifiedAttackRequirements"`
	ModifiedAttackVector              string  `json:"modifiedAttackVector"`
	ModifiedPrivilegesRequired        string  `json:"modifiedPrivilegesRequired"`
	ModifiedSubAvailabilityImpact     string  `json:"modifiedSubAvailabilityImpact"`
	ModifiedSubConfidentialityImpact  string  `json:"modifiedSubConfidentialityImpact"`
	ModifiedSubIntegrityImpact        string  `json:"modifiedSubIntegrityImpact"`
	ModifiedUserInteraction           string  `json:"modifiedUserInteraction"`
	ModifiedVulnAvailabilityImpact    string  `json:"modifiedVulnAvailabilityImpact"`
	ModifiedVulnConfidentialityImpact string  `json:"modifiedVulnConfidentialityImpact"`
	ModifiedVulnIntegrityImpact       string  `json:"modifiedVulnIntegrityImpact"`
	PrivilegesRequired                string  `json:"privilegesRequired"`
	ProviderUrgency                   string  `json:"providerUrgency"`
	SubAvailabilityImpact             string  `json:"subAvailabilityImpact"`
	SubConfidentialityImpact          string  `json:"subConfidentialityImpact"`
	SubIntegrityImpact                string  `json:"subIntegrityImpact"`
	UserInteraction                   string  `json:"userInteraction"`
	ValueDensity                      string  `json:"valueDensity"`
	VectorString                      string  `json:"vectorString"`
	Version                           string  `json:"version"`
	VulnAvailabilityImpact            string  `json:"vulnAvailabilityImpact"`
	VulnConfidentialityImpact         string  `json:"vulnConfidentialityImpact"`
	VulnIntegrityImpact               string  `json:"vulnIntegrityImpact"`
	VulnerabilityResponseEffort       string  `json:"vulnerabilityResponseEffort"`
}

// Reference is an external reference to advisories, vendor notes, etc.
type Reference struct {
	Source string   `json:"source"`
	Tags   []string `json:"tags"`
	URL    string   `json:"url"`
}

// Weakness describes CWE-style weaknesses.
type Weakness struct {
	Description []LangValue `json:"description"`
	Source      string      `json:"source"`
	Type        string      `json:"type"`
}
