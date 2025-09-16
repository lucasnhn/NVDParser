package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"nvd_parser/cve"
	"nvd_parser/databaseInterface"
	"nvd_parser/nistInterface"
	"os"
	"os/signal"
	"runtime/debug"
	"slices"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/robfig/cron/v3"
)

func init() {
	// makes the gc more strictly clear memory, makes the process when updating all use less than 0.5GiB instead of nearly 1GiB
	debug.SetMemoryLimit(300 << 20)
}

func main() {
	status, stayUpdated, username, updateAll, updateRecent, password := handleRuntimeOptions()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGHUP)
	defer cancel()

	runStatus(ctx, status)

	pool := getDatabasePool(ctx, password, username)
	defer pool.Close()

	runUpdateAll(ctx, updateAll, pool)

	runStayUpdated(ctx, stayUpdated, pool)

	runUpdateRecent(ctx, updateRecent, pool)
}

func runStatus(ctx context.Context, condition *string) {
	if *condition != "" {
		root, err := nistInterface.FetchCVESByYear(ctx, (*condition))
		if err != nil {
			fmt.Printf("error occured when fetching cves to display status, error: %v", err)
		}
		printStatus(root.Vulnerabilities)
	}
}

func getDatabasePool(ctx context.Context, password *string, username *string) *pgxpool.Pool {
	var pool *pgxpool.Pool
	var err error
	if *password != "" {
		pool, err = databaseInterface.InitiateConnectionPGXWithUsernameAndPassword(ctx, *password, *username)
	} else {
		pool, err = databaseInterface.InitiateConnectionPGX(ctx)
	}
	if err != nil {
		log.Fatalf("init conn: %v\n", err)
	}
	return pool
}

func handleRuntimeOptions() (*string, *bool, *string, *bool, *bool, *string) {
	status := flag.String("status", "", "display status")
	flag.StringVar(status, "s", "", "display status (shorthand)")

	stayUpdated := flag.Bool("keep-updated", false, "runs continually keeping the database up to date, with scans for updates every 15 minutes")
	flag.BoolVar(stayUpdated, "k", false, "runs continually keeping the database up to date, with scans for updates every 15 minutes (shorthand)")

	username := flag.String("username", "postgres", "username to connect to the database with")
	flag.StringVar(username, "u", "postgres", "username to connect to the database with")

	updateAll := flag.Bool("update-all", false, "Run update on all CVEs, this is strongly reccomended to have an accurate clone of NIST NVD if not updated withi 8 days")
	flag.BoolVar(updateAll, "a", false, "Run update on all CVEs(shorthand)")

	updateRecent := flag.Bool("update-recent", false, "Run update on data from NIST from last 8 days, then exits")
	flag.BoolVar(updateRecent, "r", false, "Run update on data from NIST from last 8 days, then exits (shorthand)")

	password := flag.String("password", "", "Supply password for postgres database to avoid prompt")
	flag.StringVar(password, "p", "", "Supply password for postgres database to avoid prompt (shorthand)")

	flag.Parse()
	return status, stayUpdated, username, updateAll, updateRecent, password
}

func runUpdateAll(ctx context.Context, condition *bool, pool *pgxpool.Pool) {
	if *condition {
		for _, year := range getYears() {
			fmt.Printf("updating for year: %v\n", year)
			var cvesP *[]cve.CVE
			{
				root, err := nistInterface.FetchCVESByYear(ctx, year)
				if err != nil {
					fmt.Printf("error occured in getting cves by year (%v), error: %v\n", year, err)
				}
				cvesP = getCVESFromVulns(root.Vulnerabilities)
			}
			err := databaseInterface.UpdateCVES(ctx, pool, cvesP)
			if err != nil {
				fmt.Printf("error occured updating cves, error: %v\n", err)
			}

		}
	}
}

func runStayUpdated(ctx context.Context, condition *bool, pool *pgxpool.Pool) {
	if *condition {
		update(ctx, pool) // runs first then every 10 minutes
		c := cron.New()
		_, err := c.AddFunc("@every 10m", func() { update(ctx, pool) })
		if err != nil {
			fmt.Printf("error occured adding function with cron, error: %v\n", err)
		}
		c.Start()
		<-ctx.Done()
	}
}

func runUpdateRecent(ctx context.Context, condition *bool, pool *pgxpool.Pool) {
	if *condition {
		update(ctx, pool)
	}
}

func appendValidDedup(target *[]cve.CVE, seen map[string]struct{}, vulns []cve.Vulnerability) {
	for _, v := range vulns {
		cv := v.CVE
		if cv.VulnStatus == "Rejected" {
			continue
		}
		if cv.Metrics.CvssMetricV2 == nil && cv.Metrics.CvssMetricV30 == nil &&
			cv.Metrics.CvssMetricV31 == nil && cv.Metrics.CvssMetricV40 == nil {
			continue
		}
		if _, ok := seen[cv.ID]; ok {
			continue
		}
		*target = append(*target, cv)
		seen[cv.ID] = struct{}{}
	}
}

func getYears() []string {
	currentYear := time.Now().Year()
	startYear := 2002
	years := make([]string, 0, currentYear-startYear+1)
	for y := startYear; y <= currentYear; y++ {
		years = append(years, fmt.Sprintf("%d", y))
	}
	return years
}

func appendValidCVE(cves []cve.CVE, cve cve.CVE) []cve.CVE {
	if (cve.VulnStatus != "Rejected") && (cve.Metrics.CvssMetricV2 != nil || cve.Metrics.CvssMetricV30 != nil || cve.Metrics.CvssMetricV31 != nil || cve.Metrics.CvssMetricV40 != nil) {
		cves = append(cves, cve)
	}
	return cves
}

func getCVESFromVulns(vulns []cve.Vulnerability) *[]cve.CVE {
	result := make([]cve.CVE, 0)
	for _, vuln := range vulns {
		cve := vuln.CVE
		if (cve.VulnStatus != "Rejected") && (cve.Metrics.CvssMetricV2 != nil || cve.Metrics.CvssMetricV30 != nil || cve.Metrics.CvssMetricV31 != nil || cve.Metrics.CvssMetricV40 != nil) {
			result = append(result, cve)
		}
	}
	return &result
}

func update(ctx context.Context, pool *pgxpool.Pool) {
	fmt.Println("running update on cves")
	recent, modified, err := nistInterface.CheckIfOOD()
	if err != nil {
		fmt.Printf("check if out of date failed, error: %v\n", err)
		return
	}
	var cvesP *[]cve.CVE
	seen := make(map[string]struct{}, 50_000)
	{
		cves := make([]cve.CVE, 0)
		cvesP = &cves
	}
	if recent {
		root, err := nistInterface.FetchCVESByYear(ctx, "recent")
		if err != nil {
			fmt.Printf("erro occured fetching cves from NVD with error: %v\n", err)
			return
		}

		appendValidDedup(cvesP, seen, root.Vulnerabilities)
		// *cvesP = append(*cvesP, *getCVESFromVulns(root.Vulnerabilities)...)
		fmt.Printf("%v new cves recently added were found on NIST NVD\n", len(*cvesP))
	}

	if modified {
		root, err := nistInterface.FetchCVESByYear(ctx, "modified")
		if err != nil {
			fmt.Printf("erro occured fetching cves from NVD with error: %v\n", err)
			return
		}
		appendValidDedup(cvesP, seen, root.Vulnerabilities)
		// appendUniqueCVEs(cvesP, *getCVESFromVulns(root.Vulnerabilities)...)
		fmt.Printf("%v newly modified cves were found on NIST NVD\n", len(*cvesP))
	}
	if !modified && !recent {
		fmt.Println("No updates were found for modified or recent")
	} else {
		err = databaseInterface.UpdateCVES(ctx, pool, cvesP)
	}
	if err != nil {
		fmt.Printf("error occured during updating cves, error: %v\n", err)
	}

}

func appendUniqueCVEs(slice *[]cve.CVE, elems ...cve.CVE) {
	for _, e := range elems {
		if !slices.ContainsFunc(*slice, func(c cve.CVE) bool { return c.ID == e.ID }) {
			*slice = append(*slice, e)
		}
	}
}

func failingJsonParse(obj any) string {
	result, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		fmt.Println(err)
	}
	return string(result)
}

func printStatus(vulneravilities []cve.Vulnerability) {
	emptyMetricInfo := make(map[string]int)
	fullMetricInfo := make(map[string]int)
	// listOfvulnStatus := []string{}

	for _, vulnerability := range vulneravilities {
		cve := vulnerability.CVE
		if cve.Metrics.CvssMetricV31 == nil {
			emptyMetricInfo[cve.VulnStatus] += 1
		} else {
			fullMetricInfo[cve.VulnStatus] += 1
		}
	}

	emptyj, err := json.MarshalIndent(emptyMetricInfo, "", "    ")
	fullj, err := json.MarshalIndent(fullMetricInfo, "", "    ")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("emtpy: \n" + string(emptyj))
	fmt.Println("full: \n" + string(fullj))
}
