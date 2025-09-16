
Here’s a clean, descriptive **README.md** draft for your program:

---

# CVE Updater

This tool synchronizes a local PostgreSQL database with the latest CVE (Common Vulnerabilities and Exposures) data from the [NIST NVD](https://nvd.nist.gov/).
It supports both one-time updates and continuous syncing to keep your database current.


## Database setup

To setup the database to begin mirroring nvd in postgresql database, you must first create the database nvd, and run the [schema.sql](schema.sql) on the nvd database, ensure the user you want to use is authorized on the database.


It is recommended increase max_wal_size in postgreql.conf from defalt e.g. 5GB to avoid excessive postgres I/O wait times due to checkpoints during large COPY operations from update-all

---

## Usage

```bash
cve-updater [options]
```

---

## Options

### Update Options

* `-a`, `-update-all`
  Run a full update on **all CVEs**.
  Recommended if the database has not been updated in more than 8 days, to ensure a complete and accurate clone of the NVD.

* `-r`, `-update-recent`
  Update CVE data from the **last 8 days**, then exit.
  Faster than a full update and suitable for frequent runs.

* `-k`, `-keep-updated`
  Run continuously, checking for new CVEs every **15 minutes** and updating the database automatically.
  Ideal for keeping the database in sync without manual intervention.

---

### Database Authentication

* `-u string`, `-username string`
  Database username. Defaults to `"postgres"`.

* `-p string`, `-password string`
  Database password. Supplying it here prevents the program from prompting interactively.

---

### Status

* `-s string`, `-status string`
  Display database update status. Useful for verifying whether your local copy is up to date.

---

## Examples

* Update **all CVEs**:

  ```bash
  cve-updater -a
  ```

* Update only **recent CVEs** (last 8 days):

  ```bash
  cve-updater -r
  ```

* Run in **continuous mode** (updates every 15 minutes):

  ```bash
  cve-updater -k
  ```

* Connect with custom credentials:

  ```bash
  cve-updater -u myuser -p mypassword -a
  ```

* Check database **status**:

  ```bash
  cve-updater -s
  ```

---

## Notes

* Use `-update-all` if your database has not been updated recently (more than 8 days).
* Continuous mode (`-k` / `-keep-updated`) is the simplest option to keep database updated, however, running recent update (`-r` / `-update-recent`) scheduled with e.g. a crontab entry is also a good option
