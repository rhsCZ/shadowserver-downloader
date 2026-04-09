# Compile

## Requirements

Required packages on Debian/Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y g++ make libcurl4-openssl-dev libsqlite3-dev libssl-dev
```

## Build

Release build:

```bash
make
```

or:

```bash
make release
```

Output:

```text
shadowserver-downloader
```

Release uses:

- `-O3`
- `strip`

Debug build:

```bash
make debug
```

Output:

```text
shadowserver-downloader-debug
```

Debug uses:

- `-O0`
- `-g`

Clean:

```bash
make clean
```
