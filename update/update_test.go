package update

import (
	"nvd_parser/cve"
	"os"
	"testing"
)

// Shared fixtures initialized once for the whole package (before-all).
var fixtures struct {
	// metrics
	MetricsNil     cve.Metrics
	MetricsV31     cve.Metrics
	MetricsV2Empty cve.Metrics

	// inputs for getCVESFromVulns
	VulnsForGetCves []cve.Vulnerability

	// inputs for appendValidUnique
	Batch1 []cve.Vulnerability
	Batch2 []cve.Vulnerability
}

// TestMain acts like a beforeAll: runs once before all tests in this package.
func TestMain(m *testing.M) {
	// Build common metrics
	fixtures.MetricsNil = cve.Metrics{}                                 // all slices nil
	fixtures.MetricsV31 = cve.Metrics{CvssMetricV31: []cve.CvssV3x{{}}} // v3.1 present
	fixtures.MetricsV2Empty = cve.Metrics{CvssMetricV2: []cve.CvssV2{}} // non-nil (empty) v2 slice

	// Inputs for getCVESFromVulns
	fixtures.VulnsForGetCves = []cve.Vulnerability{
		{CVE: cve.CVE{
			ID:         "REJ1",
			VulnStatus: "Rejected",
			Metrics:    fixtures.MetricsV31, // rejected -> should be excluded
		}},
		{CVE: cve.CVE{
			ID:         "NIL0",
			VulnStatus: "Analyzed",
			Metrics:    fixtures.MetricsNil, // all metric slices nil -> excluded
		}},
		{CVE: cve.CVE{
			ID:         "INC3",
			VulnStatus: "Analyzed",
			Metrics:    fixtures.MetricsV31, // include
		}},
		{CVE: cve.CVE{
			ID:         "INC4",
			VulnStatus: "Under Investigation",
			Metrics:    fixtures.MetricsV2Empty, // non-nil slice -> include per current predicate
		}},
	}

	// Inputs for appendValidUnique — batch1 then batch2
	fixtures.Batch1 = []cve.Vulnerability{
		{CVE: cve.CVE{ID: "rej", VulnStatus: "Rejected", Metrics: fixtures.MetricsV31}},   // rejected -> skip
		{CVE: cve.CVE{ID: "nil", VulnStatus: "Analyzed", Metrics: fixtures.MetricsNil}},   // all nil -> skip
		{CVE: cve.CVE{ID: "A", VulnStatus: "Analyzed", Metrics: fixtures.MetricsV31}},     // include
		{CVE: cve.CVE{ID: "B", VulnStatus: "Analyzed", Metrics: fixtures.MetricsV2Empty}}, // include (non-nil)
		{CVE: cve.CVE{ID: "A", VulnStatus: "Analyzed", Metrics: fixtures.MetricsV31}},     // duplicate -> skip
	}
	fixtures.Batch2 = []cve.Vulnerability{
		{CVE: cve.CVE{ID: "C", VulnStatus: "Under Investigation", Metrics: fixtures.MetricsV31}}, // new -> include
		{CVE: cve.CVE{ID: "B", VulnStatus: "Analyzed", Metrics: fixtures.MetricsV31}},            // seen -> skip
		{CVE: cve.CVE{ID: "rej2", VulnStatus: "Rejected", Metrics: fixtures.MetricsV31}},         // rejected -> skip
	}

	code := m.Run()
	os.Exit(code)
}

func TestGetCVESFromVulns(t *testing.T) {
	got := getValidCVESFromVulns(fixtures.VulnsForGetCves) // returns *[]cve.CVE in your current code
	if got == nil {
		t.Fatalf("got nil slice pointer")
	}

	// Expected: only the two non-rejected entries with any metric present.
	wantIDs := []string{"INC3", "INC4"}

	// Assertion 1: result length is exactly 2 — catches the preallocation bug.
	if len(*got) != len(wantIDs) {
		t.Fatalf("unexpected result length: got %d, want %d (preallocation bug?)", len(*got), len(wantIDs))
	}

	// Assertion 2: ensure there are no zero-valued CVEs (would appear if preallocated then appended).
	for i, c := range *got {
		if c.ID == "" {
			t.Fatalf("result[%d] is zero-valued CVE (preallocation bug)", i)
		}
	}

	// Assertion 3: order/content
	for i, id := range wantIDs {
		if (*got)[i].ID != id {
			t.Fatalf("result[%d].ID = %q, want %q", i, (*got)[i].ID, id)
		}
	}
}

func TestAppendValidUnique_Batch1(t *testing.T) {
	var target []cve.CVE
	seen := make(map[string]struct{})

	appendValidUnique(&target, seen, fixtures.Batch1)

	// Expect A and B only (order preserved)
	if len(target) != 2 {
		t.Fatalf("after batch1: got %d CVEs, want 2", len(target))
	}
	if target[0].ID != "A" || target[1].ID != "B" {
		t.Fatalf("after batch1: got order [%s, %s], want [A, B]", target[0].ID, target[1].ID)
	}

	// Seen should contain A and B only
	if _, ok := seen["A"]; !ok {
		t.Errorf("after batch1: expected A in seen")
	}
	if _, ok := seen["B"]; !ok {
		t.Errorf("after batch1: expected B in seen")
	}
	if _, ok := seen["rej"]; ok {
		t.Errorf("after batch1: rejected ID should not be in seen")
	}
	if _, ok := seen["nil"]; ok {
		t.Errorf("after batch1: nil-metrics ID should not be in seen")
	}
}

func TestAppendValidUnique_Batch2(t *testing.T) {
	// Seed with A and B already present
	target := []cve.CVE{
		{ID: "A"},
		{ID: "B"},
	}
	seen := map[string]struct{}{
		"A": {},
		"B": {},
	}

	appendValidUnique(&target, seen, fixtures.Batch2)

	// Expect C appended after A, B
	if len(target) != 3 {
		t.Fatalf("after batch2: got %d CVEs, want 3", len(target))
	}
	if target[2].ID != "C" {
		t.Fatalf("after batch2: expected last element ID = C, got %s", target[2].ID)
	}

	// Seen should contain C; rejected must not be present
	if _, ok := seen["C"]; !ok {
		t.Errorf("after batch2: expected C in seen")
	}
	if _, ok := seen["rej2"]; ok {
		t.Errorf("after batch2: rejected ID should not be in seen")
	}
}
