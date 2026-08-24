# 部署说明

> 英文版：参见 [DEPLOY.en.md](DEPLOY.en.md)。

## 前置条件

- Go 1.22+（仅构建时需要；运行只需编译产物二进制）
- cep-engine 已部署并可通过 `cepEngine.baseUrl` 访问
- mib-parser 生成的 `oid-database.db` 已持久化（`oidMap.path` 指向它）。全量库在
  mib-parser 产物目录生成，部署时拷贝到 daemon 目录，例如：

  ```bash
  # 从 mib-parser 全量产物拷贝到本机部署位置
  mkdir -p /opt/trap-daemon
  cp D:/63.CEP/mib-parser/output/oid-database.db /opt/trap-daemon/oid-database.db
  # 然后在 config.yaml 中 oidMap.path 指向 /opt/trap-daemon/oid-database.db
  ```

## 构建

**Linux / WSL**

```bash
go build -o bin/trapd ./cmd/trapd
```

**Windows**

```bat
go build -o bin\trapd.exe .\cmd\trapd
```

**WSL 内原生编译**（若需在 Linux 环境内编译）

```bash
# 首次：安装 Go（此处以官方二进制免 root 安装为例）
export GOROOT=/home/Ken/go GOPATH=/home/Ken/gopath GOSUMDB=off
export PATH=/home/Ken/go/bin:$PATH
go version

# 编译
cd /mnt/d/63.CEP/trap-daemon   # 或部署目录
make build-linux-amd64          # 或 CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/trapd ./cmd/trapd
```

> 说明：若 `$HOME` 被 WSL 重定向到 Windows 路径（如 `C:\Users\<user>`），需显式
> 设置 `GOROOT`、`GOPATH`，并将 `GOPATH` 指向 Linux 文件系统（如
> `/home/<user>/gopath`），避免 GOPATH/GOROOT 冲突与模块缓存落到 Windows 盘。
> `GOSUMDB=off` 用于跳过对 `sum.golang.org` 的校验（受限网络下）。

## 运行（前台）

**Linux / WSL**

```bash
cp config.example.yaml config.yaml
# 编辑 config.yaml：设置 oidMap.path 与 cepEngine.baseUrl
./bin/trapd --config config.yaml
```

**Windows**

```bat
copy config.example.yaml config.yaml
:: 编辑 config.yaml
bin\trapd.exe --config config.yaml
```

## 监听 162 端口权限

- **Linux**：`trapd` 以 root 运行时监听 162；以普通用户运行请改用高位端口（如
  `:1162`），或在 `/etc/sysctl.conf` 中允许非特权端口绑定（不推荐）：

  ```bash
  sudo sysctl -w net.ipv4.ip_unprivileged_port_start=0
  ```

- **Windows**：监听 162 需要以**管理员身份**运行 cmd/PowerShell 启动，否则改用
  `:1162`。

## Linux systemd 服务（单实例）

`/etc/systemd/system/trap-daemon.service`：

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
# 若使用日志文件，交由 systemd 或外部轮转管理
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now trap-daemon
```

## Windows 服务（可选）

可用 [WinSW](https://github.com/winsw/winsw) 或 NSSM 将 `trapd.exe` 注册为 Windows
服务，实现开机自启与崩溃自动重启。以 NSSM 为例：

```bat
nssm install TrapDaemon "C:\trap-daemon\bin\trapd.exe" "--config C:\trap-daemon\config.yaml"
nssm set TrapDaemon AppDirectory C:\trap-daemon
nssm set TrapDaemon Start SERVICE_AUTO_START
nssm set TrapDaemon AppStdout C:\trap-daemon\trapd.out.log
nssm set TrapDaemon AppStderr C:\trap-daemon\trapd.err.log
nssm start TrapDaemon
```

> 若需常驻后台且无需系统服务，也可用 `Start-Process`（PowerShell）或计划任务
> 「开机启动」方式运行。

## Active-Active 多实例

为每个实例创建独立 systemd 服务（或在不同主机部署），所有实例：

1. 监听 UDP 162（同一主机多实例需用不同端口 + 外部流量分发，或不同主机）
2. 指向**同一** cep-engine 与**同一** `oid-database.db`
3. 各自转发，由 cep-engine `TransportDeduplicator`（TTL 10s）去重

无需选主、无 failover 延迟。任一实例宕机不影响整体收包。

## 验证

- **Linux**：确认监听 `ss -ulnp | grep 162`；**Windows**：`netstat -an | findstr 162`
- 检查自监控：`curl http://127.0.0.1:9091/metrics`
- 确认 cep-engine 收到事件：`curl -s "http://<cep-engine>:8080/api/v1/health"`
- 用 `snmptrap`（Linux）模拟上报验证：

```bash
# v2c
snmptrap -v2c -c public <trapd-ip> "" \
  1.3.6.1.6.3.1.1.5.3 \
  1.3.6.1.2.1.2.2.1.1.3 i 3 \
  1.3.6.1.2.1.2.2.1.2.3 s "eth0"
```

Windows 下可用 `snmp.exe` 图形工具或抓包（`pktmon`）验证收包。
