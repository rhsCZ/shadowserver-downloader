# Shadowserver Downloader

A small C++ utility for downloading reports from the Shadowserver API.

The program:
- calls `reports/list`
- reads report `id` values from the response
- downloads new reports from `https://dl.shadowserver.org/<id>`
- stores downloaded report IDs in an SQLite database
- can clean or selectively remove database records without calling the API
- uses a fixed configuration file at `/etc/shadowserver/config.conf`

It uses:
- `libcurl`
- `sqlite3`
- `OpenSSL`
- `nlohmann/json` via the bundled `json.hpp`

## Files

- [USAGE.MD](USAGE.MD) describes runtime usage and arguments
- [COMPILE.MD](COMPILE.MD) describes compilation
- [INSTALL.MD](INSTALL.MD) describes installation
- [LICENSE.MD](LICENSE.MD) contains the GPLv3 license

## Features

- supports `--date`
- supports `--from-date`
- supports `--from-to-date`
- supports `--clean-db`
- supports `--remove-id-date`
- accepts both `YYYY-MM-DD` and `DD-MM-YYYY`
- skips already downloaded reports using SQLite
- stores `reported_at` from the API `timestamp` field
- optional `logfile`
- optional `download_path`
- optional `database_path`

## Default paths

- configuration: `/etc/shadowserver/config.conf`
- database: `/var/shadowserver-reports.db`

If not configured:
- `download_path` defaults to the directory containing the binary
- `logfile` is disabled
- `database_path` defaults to `/var/shadowserver-reports.db`

## Example configuration

See [config.conf.example](config.conf.example).

## Quick start

```bash
make release
sudo install -m 0755 shadowserver-downloader /usr/local/bin/shadowserver-downloader
sudo mkdir -p /etc/shadowserver
sudo cp config.conf.example /etc/shadowserver/config.conf
sudoedit /etc/shadowserver/config.conf
shadowserver-downloader --date 2026-04-08
```
