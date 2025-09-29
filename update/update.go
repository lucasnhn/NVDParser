package update

import (
	"context"
	"fmt"
	"nvd_parser/constants"
	"nvd_parser/cve"
	"nvd_parser/databaseInterface"
	"nvd_parser/nistInterface"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/robfig/cron/v3"
)

func getValidCVESFromVulns(vulns []cve.Vulnerability) *[]cve.CVE {
	result := make([]cve.CVE, 0, len(vulns))
	for _, vuln := range vulns {
		cve := vuln.CVE
		if cve.IsValid() {
			result = append(result, cve)
		}
	}
	return &result
}

func RunUpdateAll(ctx context.Context, condition *bool, pool *pgxpool.Pool) {
	if *condition {
		for _, year := range getYears() {
			fmt.Printf("updating for year: %v\n", year)
			emptyList := make([]cve.CVE, 0)
			var cvesP *[]cve.CVE = &emptyList
			{
				root, err := nistInterface.FetchCVESByYear(ctx, year)
				if err != nil {
					fmt.Printf("error occured in getting cves by year (%v), error: %v\n", year, err)
				}
				cvesP = getValidCVESFromVulns(root.Vulnerabilities)
			}
			err := databaseInterface.UpdateCVES(ctx, pool, cvesP)
			if err != nil {
				fmt.Printf("error occured updating cves, error: %v\n", err)
			}

		}
	}
}

func RunStayUpdated(ctx context.Context, condition *bool, pool *pgxpool.Pool) {
	if *condition {
		update(ctx, pool) // runs first, then scheduled
		c := cron.New()
		_, err := c.AddFunc("@every "+strconv.FormatInt(constants.UpdateTime, 10)+"m", func() { update(ctx, pool) }) // runs update function every updateTime minutes
		if err != nil {
			fmt.Printf("error occured adding function with cron, error: %v\n", err)
		}
		c.Start()
		<-ctx.Done()
	}
}

func RunUpdateRecent(ctx context.Context, condition *bool, pool *pgxpool.Pool) {
	if *condition {
		update(ctx, pool)
	}
}

func appendValidUnique(target *[]cve.CVE, seen map[string]struct{}, vulns []cve.Vulnerability) {
	for _, v := range vulns {
		cve := v.CVE
		if !cve.IsValid() {
			continue
		}
		if _, ok := seen[cve.ID]; ok {
			continue
		}
		*target = append(*target, cve)
		seen[cve.ID] = struct{}{}
	}
}

func getYears() []string {
	currentYear := time.Now().Year()
	startYear := 2002 // The year for original cve dumps, containing prior years cves starting from 1999
	years := make([]string, 0, currentYear-startYear+1)
	for y := startYear; y <= currentYear; y++ {
		years = append(years, fmt.Sprintf("%d", y))
	}
	return years
}

func update(ctx context.Context, pool *pgxpool.Pool) {
	fmt.Println("running update on cves")
	recent, modified, err := nistInterface.CheckIfOOD()
	if err != nil {
		fmt.Printf("check if out of date failed, error: %v\n", err)
		return
	}
	var cvesP *[]cve.CVE
	seen := make(map[string]struct{}, 0)
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

		appendValidUnique(cvesP, seen, root.Vulnerabilities)
		// *cvesP = append(*cvesP, *getCVESFromVulns(root.Vulnerabilities)...)
		fmt.Printf("%v new cves recently added were found on NIST NVD\n", len(*cvesP))
	}

	if modified {
		root, err := nistInterface.FetchCVESByYear(ctx, "modified")
		if err != nil {
			fmt.Printf("erro occured fetching cves from NVD with error: %v\n", err)
			return
		}
		appendValidUnique(cvesP, seen, root.Vulnerabilities)
		fmt.Printf("%v newly modified cves were found on NIST NVD\n", len(*cvesP))
	}
	if !modified && !recent {
		fmt.Println("Database allready up to date")
	} else {
		err = databaseInterface.UpdateCVES(ctx, pool, cvesP)
	}
	if err != nil {
		fmt.Printf("error occured during updating cves, error: %v\n", err)
	}

}
