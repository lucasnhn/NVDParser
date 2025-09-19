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
	"strconv"
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
	var password *string
	status, stayUpdated, username, updateAll, updateRecent, password, port, host, dbname := handleRuntimeOptions()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGHUP)
	defer cancel()

	runStatus(ctx, status)

	err := loadEnvIfExists(password, username, host, dbname, port)
	if err != nil {
		log.Fatalf("Error occured during argument handling: %v", err)
	}

	pool := getDatabasePool(ctx, password, username, port, host, dbname)
	defer pool.Close()

	runUpdateAll(ctx, updateAll, pool)

	runStayUpdated(ctx, stayUpdated, pool)

	runUpdateRecent(ctx, updateRecent, pool)
}

// loadEnvIfExists checks for environment variables with prefix NVD_PARSER_
// and sets the provided pointer variables only if the env var exists and is non-empty.
// If both a flag (changed from its default) and an environment variable are set,
// it returns an error to avoid confusion.
func loadEnvIfExists(
	password *string, username *string, host *string, dbname *string, port *int,
) error {
	// defaults from handleRuntimeOptions
	defaults := map[string]any{
		"NVD_PARSER_PASSWORD": "",
		"NVD_PARSER_USERNAME": "postgres",
		"NVD_PARSER_HOST":     "localhost",
		"NVD_PARSER_DBNAME":   "nvd",
		"NVD_PARSER_PORT":     5432,
	}

	// string-based vars
	stringMapping := map[string]*string{
		"NVD_PARSER_PASSWORD": password,
		"NVD_PARSER_USERNAME": username,
		"NVD_PARSER_HOST":     host,
		"NVD_PARSER_DBNAME":   dbname,
	}

	for env, ptr := range stringMapping {
		if val, ok := os.LookupEnv(env); ok && val != "" {
			if *ptr != defaults[env].(string) { // flag changed from default
				return fmt.Errorf("conflict: %s is set, but flag value is also provided", env)
			}
			*ptr = val
		}
	}

	// special handling for port (int)
	if val, ok := os.LookupEnv("NVD_PARSER_PORT"); ok && val != "" {
		if *port != defaults["NVD_PARSER_PORT"].(int) { // flag changed from default
			return fmt.Errorf("conflict: NVD_PARSER_PORT is set, but flag value is also provided")
		}
		p, err := strconv.Atoi(val)
		if err != nil {
			return fmt.Errorf("invalid port value in NVD_PARSER_PORT it must be integer: %q", val)
		}
		*port = p
	}

	return nil
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

func getDatabasePool(ctx context.Context, password *string, username *string, port *int, host *string, dbname *string) *pgxpool.Pool {
	var pool *pgxpool.Pool
	var err error
	pool, err = databaseInterface.InitiateConnectionPGX(ctx, *username, *password, *dbname, *port, *host)
	if err != nil {
		log.Fatalf("init conn: %v\n", err)
	}
	return pool
}

func handleRuntimeOptions() (status *string, stayUpdated *bool, username *string, updateAll *bool,
	updateRecent *bool, password *string, port *int, host *string, dbname *string) {
	status = flag.String("status", "", "display status")
	flag.StringVar(status, "s", "", "display status (shorthand)")

	port = flag.Int("port", 5432, "port number of postgresql server")
	host = flag.String("host", "localhost", "host where postgresql server runs")
	dbname = flag.String("dbname", "nvd", "name of database to update based on NVD")

	stayUpdated = flag.Bool("keep-updated", false, "runs continually keeping the database up to date, with scans for updates every 15 minutes")
	flag.BoolVar(stayUpdated, "k", false, "runs continually keeping the database up to date, with scans for updates every 15 minutes (shorthand)")

	username = flag.String("username", "postgres", "username to connect to the database with")
	flag.StringVar(username, "u", "postgres", "username to connect to the database with")

	updateAll = flag.Bool("update-all", false, "Run update on all CVEs, this is strongly reccomended to have an accurate clone of NIST NVD if not updated withi 8 days")
	flag.BoolVar(updateAll, "a", false, "Run update on all CVEs(shorthand)")

	updateRecent = flag.Bool("update-recent", false, "Run update on data from NIST from last 8 days, then exits")
	flag.BoolVar(updateRecent, "r", false, "Run update on data from NIST from last 8 days, then exits (shorthand)")

	password = flag.String("password", "", "Supply password for postgres database to avoid prompt")
	flag.StringVar(password, "p", "", "Supply password for postgres database to avoid prompt (shorthand)")

	flag.Parse()
	return status, stayUpdated, username, updateAll, updateRecent, password, port, host, dbname
}

// GetNVDParserPassword checks if the environment variable NVD_PARSER_PASSWORD exists.
// If it does, returns the value (password). Otherwise, returns an empty string.
func getPassFromEnv(password *string) {
	if envPassword, exists := os.LookupEnv("NVD_PARSER_PASSWORD"); exists {
		*password = envPassword
	}
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
