# Deployment Guide

> Chinese version: see [DEPLOY.md](DEPLOY.md).

## Prerequisites

- Go 1.22+ (only needed to build; runtime just needs the compiled binary)
- cep-engine deployed and reachable via `cepEngine.baseUrl`
- mib-parser `oid-database.db` persisted (`oidMap.path` points to it). The full
  database is generated in the mib-parser output directory; copy it to the daemon
  host during deployment, e.g.:

  ```bash
  # Copy from the mib-parser full output to the local deployment location
  mkdir -p /opt/trap-daemon
  cp /path/to/mib-parser/output/oid-database.db /opt/trap-daemon/oid-database.db
  # Then set oidMap.path to /opt/trap-daemon/oid-database.db in config.yaml
  ```

## Build

**Linux / WSL**

```bash
go build -o bin/trapd ./cmd/trapd
```

**Windows**

```bat
go build -o bin\trapd.exe .\cmd\trapd
```

**Native build inside WSL** (when you want to compile within a Linux environment)

```bash
# First time: install Go (e.g. official binary tarball, no root needed)
export GOROOT=/home/Ken/go GOPATH=/home/Ken/gopath GOSUMDB=off
export PATH=/home/Ken/go/bin:$PATH
go version

# Build
cd /mnt/d/63.CEP/trap-daemon   # or your deploy dir
make build-linux-amd64          # or CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/trapd ./cmd/trapd
```

> Note: if WSL remaps `$HOME` to a Windows path (e.g. `C:\Users\<user>`), set
> `GOROOT` and `GOPATH` explicitly and point `GOPATH` to the Linux filesystem
> (e.g. `/home/<user>/gopath`) to avoid GOROOT/GOPATH conflicts and keep the
> module cache off the Windows drive. `GOSUMDB=off` skips `sum.golang.org`
> verification (useful on restricted networks).

## Run (foreground)

**Linux / WSL**

```bash
cp config.example.yaml config.yaml
# edit config.yaml: set oidMap.path and cepEngine.baseUrl
./bin/trapd --config config.yaml
```

**Windows**

```bat
copy config.example.yaml config.yaml
:: edit config.yaml
bin\trapd.exe --config config.yaml
```

## Listening on port 162

- **Linux**: `trapd` listens on 162 when run as root; otherwise use a high port
  (e.g. `:1162`), or allow unprivileged port binding in `/etc/sysctl.conf` (not
  recommended):

  ```bash
  sudo sysctl -w net.ipv4.ip_unprivileged_port_start=0
  ```

- **Windows**: listening on 162 requires an **Administrator** shell; otherwise use
  `:1162`.

## Linux systemd service (single instance)

`/etc/systemd/system/trap-daemon.service`:

```ini
[Unit]
Description=SNMP Trap Daemon
After=network.target

[Service]
ExecStart=/opt/trap-daemon/bin/trapd --config /opt/trap-daemon/config.yaml
WorkingDirectory=/opt/trap-daemon
Restart=always
RestartSec=3
User=trapd
Group=trapd
# Use systemd or an external log rotator if logging to a file
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now trap-daemon
```

## Windows service (optional)

Use [WinSW](https://github.com/winsw/winsw) or NSSM to register `trapd.exe` as a
Windows service for auto-start and crash restart. NSSM example:

```bat
nssm install TrapDaemon "C:\trap-daemon\bin\trapd.exe" "--config C:\trap-daemon\config.yaml"
nssm set TrapDaemon AppDirectory C:\trap-daemon
nssm set TrapDaemon Start SERVICE_AUTO_START
nssm set TrapDaemon AppStdout C:\trap-daemon\trapd.out.log
nssm set TrapDaemon AppStderr C:\trap-daemon\trapd.err.log
nssm start TrapDaemon
```

> To keep it running in the background without a service, you can also use
> `Start-Process` (PowerShell) or a scheduled task at logon.

## Active-Active multi-instance

Create a separate systemd service per instance (or deploy on different hosts).
All instances:

1. listen on UDP 162 (multiple instances on one host need different ports plus
   external traffic distribution, or different hosts)
2. point to the **same** cep-engine and the **same** `oid-database.db`
3. each forwards independently; cep-engine `TransportDeduplicator` (TTL 10s)
   deduplicates

No leader election, no failover delay. An instance outage does not affect the
others.

## Verification

- **Linux**: check listening `ss -ulnp | grep 162`; **Windows**:
  `netstat -an | findstr 162`
- Check self-monitoring: `curl http://127.0.0.1:9091/metrics`
- Confirm cep-engine receives events: `curl -s "http://<cep-engine>:8080/api/v1/health"`
- Simulate a trap with `snmptrap` (Linux):

```bash
# v2c
snmptrap -v2c -c public <trapd-ip> "" \
  1.3.6.1.6.3.1.1.5.3 \
  1.3.6.1.2.1.2.2.1.1.3 i 3 \
  1.3.6.1.2.1.2.2.1.2.3 s "eth0"
```

On Windows, use the `snmp.exe` GUI or packet capture (`pktmon`) to verify
reception.
