package databaseInterface

import (
	"encoding/json"
	"math/rand"
	"nvd_parser/cve"
	"os"
	"testing"
	"time"
)

var testRoot cve.Root

// TestMain runs setup before any other tests
func TestMain(m *testing.M) {
	setup()
	code := m.Run()
	os.Exit(code)
}

// setup reads and parses the json file into testRoot
func setup() {
	data, err := os.ReadFile("testingData.json")
	if err != nil {
		panic("Failed to read test data: " + err.Error())
	}
	if err := json.Unmarshal(data, &testRoot); err != nil {
		panic("Failed to parse test data: " + err.Error())
	}
}

func TestPartitionInPlace(t *testing.T) {
	numTrues := 12
	numFalses := 15

	trueSlice := make([]bool, numTrues)
	for i := range trueSlice {
		trueSlice[i] = true
	}

	falseSlice := make([]bool, numFalses) // All elements are false by default

	combined := append(trueSlice, falseSlice...)

	// Create a local, seeded rand.Rand instance (deterministic)
	rng := rand.New(rand.NewSource(3))
	rng.Shuffle(len(combined), func(i, j int) { combined[i], combined[j] = combined[j], combined[i] })

	partitionIndex := partitionInPlace(&combined, func(b bool) bool { return b })

	// Check: all values before partitionIndex should be true, rest should be false
	for i := 0; i < partitionIndex; i++ {
		if !combined[i] {
			t.Errorf("Expected true at index %d, got false", i)
		}
	}
	for i := partitionIndex; i < len(combined); i++ {
		if combined[i] {
			t.Errorf("Expected false at index %d, got true", i)
		}
	}

	t.Logf("Partitioned result: %v", combined)
}

func TestGetPartitions_Classifications(t *testing.T) {
	// Prepare input CVEs
	cveList := []cve.CVE{}
	for _, vulnerability := range testRoot.Vulnerabilities {
		cveList = append(cveList, vulnerability.CVE)
	}
	now := time.Now()

	// Assign each CVE to a group (round robin):
	// - 1/3 new (not in dates)
	// - 1/3 out-of-date (OOD: in dates, LastModified after stored)
	// - 1/3 up-to-date (in dates, LastModified not after stored)
	storedDateMap := map[string]time.Time{}
	expectedOutOfDateIDs := map[string]struct{}{}
	expectedUpToDateIDs := map[string]struct{}{}
	expectedNewIDs := map[string]struct{}{}

	for i, cve := range cveList {
		switch i % 3 {
		case 0:
			// New: not in storedDateMap
			expectedNewIDs[cve.ID] = struct{}{}
		case 1:
			// Out-of-date: present in storedDateMap, but CVE is newer
			storedDateMap[cve.ID] = now.Add(-24 * time.Hour)
			expectedOutOfDateIDs[cve.ID] = struct{}{}
			// Simulate LastModified in future (should be later than stored)
			cve.LastModified = now.Add(1 * time.Hour).Format(time.RFC3339)
			cveList[i] = cve
		case 2:
			// Up-to-date: present in storedDateMap, CVE is not newer
			storedDateMap[cve.ID] = now.Add(-24 * time.Hour)
			expectedUpToDateIDs[cve.ID] = struct{}{}
			// Simulate LastModified in past (should not be later than stored)
			cve.LastModified = now.Add(-48 * time.Hour).Format(time.RFC3339)
			cveList[i] = cve
		}
	}

	// Run partitioning
	newCVEs, outOfDateCVEs := getPartitions(&cveList, storedDateMap)

	// Build sets for outputs
	actualNewCVEIDs := make(map[string]struct{}, len(newCVEs))
	for _, cve := range newCVEs {
		actualNewCVEIDs[cve.ID] = struct{}{}
	}
	actualOutOfDateCVEIDs := make(map[string]struct{}, len(outOfDateCVEs))
	for _, cve := range outOfDateCVEs {
		actualOutOfDateCVEIDs[cve.ID] = struct{}{}
	}
	// Up-to-date: all present in expectedUpToDateIDs, but not in actualNewCVEIDs or actualOutOfDateCVEIDs
	actualUpToDateCVEIDs := map[string]struct{}{}
	for id := range expectedUpToDateIDs {
		if _, isNew := actualNewCVEIDs[id]; !isNew {
			if _, isOOD := actualOutOfDateCVEIDs[id]; !isOOD {
				actualUpToDateCVEIDs[id] = struct{}{}
			}
		}
	}

	// Check each set for exact match
	if !areCVEIDSetsEqual(actualNewCVEIDs, expectedNewIDs) {
		t.Errorf("New CVEs mismatch.\nExpected: %v\nGot: %v", getStringSetKeys(expectedNewIDs), getStringSetKeys(actualNewCVEIDs))
	}
	if !areCVEIDSetsEqual(actualOutOfDateCVEIDs, expectedOutOfDateIDs) {
		t.Errorf("Out-of-date CVEs mismatch.\nExpected: %v\nGot: %v", getStringSetKeys(expectedOutOfDateIDs), getStringSetKeys(actualOutOfDateCVEIDs))
	}
	if !areCVEIDSetsEqual(actualUpToDateCVEIDs, expectedUpToDateIDs) {
		t.Errorf("Up-to-date CVEs mismatch.\nExpected: %v\nGot: %v", getStringSetKeys(expectedUpToDateIDs), getStringSetKeys(actualUpToDateCVEIDs))
	}

	// Log for inspection
	t.Logf("New: %d, Out-of-date: %d, Up-to-date: %d", len(actualNewCVEIDs), len(actualOutOfDateCVEIDs), len(actualUpToDateCVEIDs))
}

// Helper functions
func areCVEIDSetsEqual(firstSet, secondSet map[string]struct{}) bool {
	if len(firstSet) != len(secondSet) {
		return false
	}
	for element := range firstSet {
		if _, exists := secondSet[element]; !exists {
			return false
		}
	}
	for element := range secondSet {
		if _, exists := firstSet[element]; !exists {
			return false
		}
	}
	return true
}

func getStringSetKeys(stringSet map[string]struct{}) []string {
	keys := make([]string, 0, len(stringSet))
	for key := range stringSet {
		keys = append(keys, key)
	}
	return keys
}

