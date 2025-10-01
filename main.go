package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"nvdparser/constants/defaults"
	"nvdparser/cve"
	"nvdparser/databaseInterface"
	"nvdparser/nistInterface"
	"nvdparser/update"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"syscall"

	"github.com/jackc/pgx/v5/pgxpool"
)

func init() {
	// makes the gc more strictly clear memory, makes the process when updating all use less than 0.5GiB instead of nearly 1GiB
	debug.SetMemoryLimit(300 << 20)
}

func main() {
	var password *string
	year, stayUpdated, username, updateAll, updateRecent, password, port, host, dbname := handleRuntimeOptions()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGHUP)
	defer cancel()

	runStatus(ctx, year)

	err := loadEnvIfExists(password, username, host, dbname, port)
	if err != nil {
		log.Fatalf("Error occured during argument handling: %v", err)
	}

	pool := getDatabasePool(ctx, password, username, port, host, dbname)
	defer pool.Close()

	update.RunUpdateAll(ctx, updateAll, pool)

	update.RunStayUpdated(ctx, stayUpdated, pool)

	update.RunUpdateRecent(ctx, updateRecent, pool)
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
		"NVD_PARSER_USERNAME": defaults.Username,
		"NVD_PARSER_HOST":     defaults.Host,
		"NVD_PARSER_DBNAME":   defaults.DBName,
		"NVD_PARSER_PORT":     defaults.Port,
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

func runStatus(ctx context.Context, year *string) {
	if *year != "" {
		root, err := nistInterface.FetchCVESByYear(ctx, (*year))
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

	port = flag.Int("port", defaults.Port, "port number of postgresql server")
	host = flag.String("host", defaults.Host, "host where postgresql server runs")
	dbname = flag.String("dbname", defaults.DBName, "name of database to update based on NVD")

	stayUpdated = flag.Bool("keep-updated", false, "runs continually keeping the database up to date, with scans for updates every 15 minutes")
	flag.BoolVar(stayUpdated, "k", false, "runs continually keeping the database up to date, with scans for updates every 15 minutes (shorthand)")

	username = flag.String("username", defaults.Username, "username to connect to the database with")
	flag.StringVar(username, "u", defaults.Username, "username to connect to the database with")

	updateAll = flag.Bool("update-all", false, "Run update on all CVEs, this is strongly reccomended to have an accurate clone of NIST NVD if not updated withi 8 days")
	flag.BoolVar(updateAll, "a", false, "Run update on all CVEs(shorthand)")

	updateRecent = flag.Bool("update-recent", false, "Run update on data from NIST from last 8 days, then exits")
	flag.BoolVar(updateRecent, "r", false, "Run update on data from NIST from last 8 days, then exits (shorthand)")

	password = flag.String("password", "", "Supply password for postgres database to avoid prompt")
	flag.StringVar(password, "p", "", "Supply password for postgres database to avoid prompt (shorthand)")

	flag.Parse()
	return status, stayUpdated, username, updateAll, updateRecent, password, port, host, dbname
}

func printStatus(vulneravilities []cve.Vulnerability) {
	emptyMetricInfo := make(map[string]int)
	fullMetricInfo := make(map[string]int)

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
