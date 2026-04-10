# Install

## 1. Compile

```bash
make release
```

## 2. Install the binary

Example installation into `/usr/local/bin`:

```bash
sudo install -m 0755 shadowserver-downloader /usr/local/bin/shadowserver-downloader
```

## 3. Create the configuration

```bash
sudo mkdir -p /etc/shadowserver
sudo cp config.conf.example /etc/shadowserver/config.conf
sudo chmod 600 /etc/shadowserver/config.conf
```

Then edit:

```ini
api-key=YOUR_API_KEY
secret=YOUR_API_SECRET
```

Optional:

```ini
logfile=/var/log/shadowserver-reports.log
download_path=/var/shadowserver/reports
database_path=/var/shadowserver-reports.db
delay=0.5s
```

## 4. Permissions and directories

If configured paths do not exist, the program attempts to create:

- the directory for `logfile`
- the directory for `download_path`
- the parent directory for `database_path`

The process must have write access to:

- the target report directory
- the log directory, if logging is enabled
- the database directory

Configuration values can be overridden at runtime with CLI arguments, for example:

```bash
shadowserver-downloader --database-path /tmp/shadowserver.db --download-path /tmp/reports --delay 500ms
```

## 5. Test run

```bash
shadowserver-downloader --help
shadowserver-downloader --date 2026-04-08
shadowserver-downloader --clean-db
```

## 6. Optional cron setup

Example daily run:

```cron
15 2 * * * /usr/local/bin/shadowserver-downloader --date $(date +\%F)
```

In practice, running without `--date` is often simpler if you always want today's date:

```cron
15 2 * * * /usr/local/bin/shadowserver-downloader
```
