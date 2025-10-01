# NVD Parser

This tool synchronizes a local PostgreSQL database with the latest CVE (Common Vulnerabilities and Exposures) data from the [NIST NVD](https://nvd.nist.gov/).  
It supports both one-time updates and continuous syncing to keep your database current.

This project is not affiliated with or endorsed by NIST or the National Vulnerability Database.

## Database setup

To set up the database, create a PostgreSQL database named `nvd` and run [schema.sql](schema.sql) on it. Ensure your user has the necessary privileges.

It is recommended to increase `max_wal_size` in `postgresql.conf` (e.g., to 5GB) to avoid excessive I/O wait times during large updates.

## Usage

```bash
cve-updater [options]
```

## Options

### Update Options

* `-a`, `-update-all`  
  Run a full update on all CVEs. Use if the database hasn’t been updated in more than 8 days.

* `-r`, `-update-recent`  
  Update CVE data from the last 8 days, then exit. Suitable for frequent runs.

* `-k`, `-keep-updated`  
  Run continuously, checking for new CVEs every 15 minutes.

### Database Authentication

You can provide credentials and connection details by **either** runtime arguments (flags) **or** environment variables, but not both for the same field.

#### Runtime arguments (flags):

* `-u string`, `-username string`  
  Database username (default: `postgres`).

* `-p string`, `-password string`  
  Database password.

* `-h string`, `-host string`  
  Database host (default: `localhost`).

* `-d string`, `-dbname string`  
  Database name (default: `nvd`).

* `--port int`  
  Database port (default: `5432`).

#### Environment Variables:

Instead of flags, you can use:

- `NVD_PARSER_USERNAME`
- `NVD_PARSER_PASSWORD`
- `NVD_PARSER_HOST`
- `NVD_PARSER_DBNAME`
- `NVD_PARSER_PORT`

If both a flag and an environment variable are set for the same parameter, the program will return an error and exit.

### Status

* `-s string`, `-status string`  
  Display database update status.

## Examples

* Update all CVEs:

  ```bash
  cve-updater -a
  ```

* Update only recent CVEs:

  ```bash
  cve-updater -r
  ```

* Run in continuous mode:

  ```bash
  cve-updater -k
  ```

* Connect with custom credentials (flags):

  ```bash
  cve-updater -u myuser -p mypassword -a
  ```

* Connect with environment variables:

  ```bash
  export NVD_PARSER_USERNAME=myuser
  export NVD_PARSER_PASSWORD=mypassword
  export NVD_PARSER_HOST=localhost
  export NVD_PARSER_DBNAME=nvd
  export NVD_PARSER_PORT=5432
  cve-updater -a
  ```

* Check status:

  ```bash
  cve-updater -s
  ```

## Notes

* Use `-update-all` if your database has not been updated in over 8 days.
* Continuous mode (`-k`) is an easy way to keep updated, or you can use `-r` in a scheduled job.

## Configuration Precedence

Database connection settings can be provided with flags or environment variables (prefix `NVD_PARSER_`).  
Do not set both for the same option; if both are set, the tool will exit with an error to avoid ambiguity.
