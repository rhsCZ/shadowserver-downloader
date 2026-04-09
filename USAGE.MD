# Usage

## Run

```bash
shadowserver-downloader [--date DATE] [--from-date DATE] [--from-to-date DATE:DATE] [--clean-db] [--remove-id-date VALUE] [--help|-h]
```

## Arguments

- `--date DATE`
  downloads reports for a single day
- `--from-date DATE`
  downloads reports from the given date up to today
- `--from-to-date DATE:DATE`
  downloads reports for the given range
- `--clean-db`
  removes all database records and exits
- `--remove-id-date VALUE`
  removes database records by report ID, single date, or date range and exits
- `--help`, `-h`
  shows help

## Date formats

Supported formats:

- `YYYY-MM-DD`
- `DD-MM-YYYY`

Examples:

```bash
shadowserver-downloader --date 2026-04-08
shadowserver-downloader --date 08-04-2026
shadowserver-downloader --from-date 2026-04-01
shadowserver-downloader --from-date 01-04-2026
shadowserver-downloader --from-to-date 2026-04-01:2026-04-08
shadowserver-downloader --from-to-date 01-04-2026:08-04-2026
```

## Argument rules

- `--date` accepts only a single date
- `--from-date` accepts only a single date
- `--from-to-date` accepts only a date range
- `--date`, `--from-date`, and `--from-to-date` are mutually exclusive
- `--clean-db` and `--remove-id-date` are mutually exclusive
- `--clean-db` cannot be combined with any download date argument
- `--remove-id-date` cannot be combined with any download date argument

## Database maintenance examples

Remove one record by report ID:

```bash
shadowserver-downloader --remove-id-date 'example-report-id'
```

Remove records for one date:

```bash
shadowserver-downloader --remove-id-date 2026-04-08
shadowserver-downloader --remove-id-date 08-04-2026
```

Remove records for a date range:

```bash
shadowserver-downloader --remove-id-date 2026-04-01:2026-04-08
shadowserver-downloader --remove-id-date 01-04-2026:08-04-2026
```

Clear the whole database:

```bash
shadowserver-downloader --clean-db
```

## Configuration

The program reads configuration from:

```text
/etc/shadowserver/config.conf
```

Format:

```ini
api-key=YOUR_API_KEY
secret=YOUR_API_SECRET
# logfile=/var/log/shadowserver-reports.log
# download_path=/var/shadowserver/reports
# database_path=/var/shadowserver-reports.db
```

## Program behavior

- calls `reports/list`
- reads `id`, `timestamp`, and file name from the response
- compares `id` values against the database
- downloads only reports not already present in the database
- stores `id` and `reported_at` after a successful download

## Database

Default path:

```text
/var/shadowserver-reports.db
```

Table:

```sql
CREATE TABLE reports (
    id TEXT PRIMARY KEY,
    reported_at TEXT NOT NULL
);
```
