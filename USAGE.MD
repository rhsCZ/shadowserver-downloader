# Usage

## Run

```bash
shadowserver-downloader [--date DATE] [--from-date DATE] [--from-to-date DATE:DATE] [--clean-db] [--remove-id-date VALUE] [options] [--help|-h]
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
- `--api-key VALUE`
  overrides `api-key` from configuration
- `--secret VALUE`
  overrides `secret` from configuration
- `--logfile VALUE`
  overrides `logfile` from configuration
- `--download-path VALUE`
  overrides `download_path` from configuration
- `--database-path VALUE`
  overrides `database_path` from configuration
- `--delay VALUE`
  overrides `delay` from configuration
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
# delay=0.5s
```

`delay` controls how long the program waits between downloading individual reports.
Supported units are:

- `h` for hours
- `m` for minutes
- `s` for seconds
- `ms` for milliseconds

Examples:

```ini
delay=2s
delay=500ms
delay=0.5s
delay=1m
```

Configuration values can also be specified as command-line arguments.
Command-line arguments take precedence over values from `/etc/shadowserver/config.conf`.

Example:

```bash
shadowserver-downloader --date 2026-04-08 --download-path /tmp/reports --delay 500ms
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
