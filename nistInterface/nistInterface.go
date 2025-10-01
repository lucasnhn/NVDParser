package nistInterface

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"nvdparser/cve"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var modifiedDate time.Time = time.Unix(0, 0)
var recentDate time.Time = time.Unix(0, 0)

func CheckIfOOD() (bool, bool, error) {
	modifiedOOD := false
	recentOOD := false
	modifiedUrl := "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.meta"
	recentUrl := "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.meta"

	modified, err := fetchMetadata(modifiedUrl)
	if err != nil {
		return false, false, err
	}
	modifiedOOD = modified.LastModifiedDate.After(modifiedDate)
	modifiedDate = modified.LastModifiedDate

	recent, err := fetchMetadata(recentUrl)
	if err != nil {
		return false, false, err
	}
	recentOOD = recent.LastModifiedDate.After(recentDate)
	recentDate = recent.LastModifiedDate

	return modifiedOOD, recentOOD, nil
}

type fileMetadata struct {
	LastModifiedDate time.Time
	Size             int64
	ZipSize          int64
	GzSize           int64
	SHA256           string
}

func fetchMetadata(url string) (*fileMetadata, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to GET url %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("non-200 status code: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	lines := strings.Split(string(body), "\n")
	meta := &fileMetadata{}

	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		switch key {
		case "lastModifiedDate":
			t, err := time.Parse(time.RFC3339, val)
			if err != nil {
				return nil, fmt.Errorf("parsing lastModifiedDate failed: %w", err)
			}
			meta.LastModifiedDate = t
		case "size":
			fmt.Sscan(val, &meta.Size)
		case "zipSize":
			fmt.Sscan(val, &meta.ZipSize)
		case "gzSize":
			fmt.Sscan(val, &meta.GzSize)
		case "sha256":
			meta.SHA256 = val
		}
	}

	return meta, nil
}

func FetchCVESByYear(ctx context.Context, year string) (cve.Root, error) {
	url := "https://nvd.nist.gov/feeds/json/cve/2.0/" + "nvdcve-2.0-" + year + ".json.zip"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return cve.Root{}, fmt.Errorf("getting request for url %v failed: %w", url, err)
	}

	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return cve.Root{}, fmt.Errorf("client.Do failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		return cve.Root{}, fmt.Errorf("bad status %d: %s", resp.StatusCode, string(b))
	}

	// Optional download limit (e.g., 200 MB)
	const maxZip = 200 << 20
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, io.LimitReader(resp.Body, maxZip)); err != nil {
		return cve.Root{}, fmt.Errorf("reading from NIST failed, possibly timed out or cancelled by context, error : %w\n", err)
	}

	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		return cve.Root{}, fmt.Errorf("getting zip reader failed: %w", err)
	}

	var out cve.Root
	for _, f := range zr.File {
		if strings.HasSuffix(strings.ToLower(f.Name), ".json") {
			rc, err := f.Open()
			if err != nil {
				return cve.Root{}, fmt.Errorf("zipfile.File.Open failed: %w", err)
			}

			dec := json.NewDecoder(rc)
			var p cve.Root
			if err := dec.Decode(&p); err != nil {
				_ = rc.Close()
				return cve.Root{}, fmt.Errorf("decode %s failed: %w", f.Name, err)
			}
			_ = rc.Close()
			out = p
		}
	}

	return out, nil
}

// If any error occurs, it prints the error and terminates the program.
func ListFiles(relDir string) []string {
	base, err := filepath.Abs(relDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to resolve path: %v\n", err)
		os.Exit(1)
	}

	var out []string
	err = filepath.WalkDir(base, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		out = append(out, path)
		return nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to walk directory: %v\n", err)
		os.Exit(1)
	}

	return out
}
