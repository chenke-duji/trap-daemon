# trap-daemon

> **Language / 语言**：[English](README.en.md) | 中文

高性能、多线程的 SNMP Trap Daemon。接收网络设备上报的 SNMP Trap（v1/v2c），
将 varbind OID 通过 mib-parser 生成的 OID 数据库映射为字段名，构造 cep-engine
所需的 `RawEvent` JSON，并通过 REST HTTP 批量转发给 cep-engine。支持
**Active-Active** 多实例部署（去重由 cep-engine 的 TransportDeduplicator 负责，
daemon 本身无状态）。Kafka 作为可选转发通道预留。

## 功能特性

- **SNMP Trap 接收**：监听 UDP 162，支持 v1/v2c 解析，预留 v3 扩展点
- **OID → 字段名映射**：加载 `oid-database.properties`（mib-parser 产物），对
  varbind 完整实例 OID 做最长前缀匹配得到字段名
- **RawEvent 构造**：严格对齐 cep-engine 摄取契约
- **REST 批量转发**：worker pool 攒批 POST `/api/v1/events/batch`，指数退避重试，
  有界队列背压，满时丢弃并打印日志
- **Active-Active**：无状态多实例，去重交给 cep-engine
- **自监控**：Prometheus 文本格式 `/metrics`，含启动时间、累计 trap 数、last 5min 吞吐量
- **配置化**：YAML + 环境变量覆盖

## 架构

```
设备 ──SNMP v1/v2c Trap UDP:162──> trap-daemon
                                       │
                 ┌─────────────────────┤
                 ▼                     ▼
        gosnmp TrapListener      OID 映射表(oid-database.properties)
                 │                     │
                 ▼                     │
              TrapDecoder ────────────┤  varbind OID -> 字段名
                 ▼                     │
             RawEvent 构造 ────────────┘
                 ▼
        BatchQueue(worker pool + 背压)
                 ▼
        POST /api/v1/events/batch ──> cep-engine
                                          │
                                          ▼
                     TransportDeduplicator(Active-Active 去重)
                                          ▼
                     Groovy parser 解析 -> 告警
```

## 目录结构

```
trap-daemon/
├── cmd/trapd/main.go        # 入口：装配、优雅退出
├── internal/
│   ├── config/              # YAML 配置加载 + env 覆盖
│   ├── snmp/                # TrapDecoder 接口 + v1/v2c 实现
│   ├── oidmap/              # oid-database.properties 加载 + 最长前缀匹配
│   ├── model/               # RawEvent 模型（对齐 cep-engine 契约）
│   ├── forward/             # 批量队列/背压 + HTTP/Kafka 转发器
│   └── metrics/             # Prometheus 指标
├── config.example.yaml      # 配置示例
└── testdata/                # 测试用 OID 数据库
```

## 构建

要求 Go 1.22+（开发环境 1.26.7）。

**Windows（本机编译）**

```bat
go build -o bin\trapd.exe .\cmd\trapd
```

**Windows 交叉编译 Linux（纯 Go 项目，无需 cgo，可直接生成 Linux 版本）**

```bat
set CGO_ENABLED=0
set GOOS=linux
set GOARCH=amd64
go build -o bin\trapd-linux-amd64 .\cmd\trapd

set GOARCH=arm64
go build -o bin\trapd-linux-arm64 .\cmd\trapd
```

**Linux / WSL**

```bash
# 本机平台编译
go build -o bin/trapd ./cmd/trapd

# 交叉编译 Linux x86_64
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/trapd-linux-amd64 ./cmd/trapd

# 交叉编译 Linux aarch64
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o bin/trapd-linux-arm64 ./cmd/trapd
```

或使用 `make`（Windows 下需配合 Git Bash / WSL 中的 make）：

```bash
make build              # 本机平台
make build-linux-amd64  # Linux x86_64
make build-linux-arm64  # Linux aarch64
make build-linux        # amd64 + arm64
```

生成的二进制为**静态链接**（CGO_ENABLED=0），不依赖系统共享库，可直接部署到任意
x86_64/aarch64 Linux 发行版。已在 WSL AlmaLinux-8 原生编译（Go 1.27.0）并通过
真实 v2c trap 的「接收 → 字段名映射 → RawEvent → HTTP 转发」端到端验证。

## 配置

将 `config.example.yaml` 复制为 `config.yaml` 并填写：

- `oidMap.path`：**必填**，指向 mib-parser 生成的 `oid-database.properties`
  （本项目不内置该文件）。每次 mib-parser 新增 MIB 支持后更新并持久化该文件，
  重启 daemon 生效。
- `cepEngine.baseUrl`：**必填**，cep-engine 根地址。
- 其余项均有默认值。

支持环境变量覆盖（优先级高于 YAML）：

| 环境变量 | 说明 |
|---|---|
| `TRAPD_SNMP_LISTENADDR` | UDP 监听地址 |
| `TRAPD_SNMP_PROTOCOL` | `v1v2c` / `v3` |
| `TRAPD_SNMP_COMMUNITY` | 可选 community |
| `TRAPD_OIDMAP_PATH` | OID 数据库路径 |
| `TRAPD_CEPENGINE_BASEURL` | cep-engine 根地址 |
| `TRAPD_CEPENGINE_AUTHTOKEN` | Bearer token |
| `TRAPD_LOGGING_LEVEL` | 日志级别 |
| `TRAPD_LOGGING_FILE` | 日志文件路径 |
| `TRAPD_METRICS_ENABLED` / `TRAPD_METRICS_LISTENADDR` / `TRAPD_METRICS_PATH` | 自监控 |

## 运行

**Linux / WSL**

```bash
./bin/trapd --config config.yaml
```

以非 root 用户监听 162 端口需要权限，可将 `snmp.listenAddr` 改为 `:1162` 并在
cep-engine 采集侧使用该端口，或以 root/systemd 运行。

**Windows**

```bat
bin\trapd.exe --config config.yaml
```

Windows 下监听 162 端口同样需要管理员权限（否则改用 `:1162`），并以管理员身份
运行 cmd/PowerShell 启动。

完整部署（含 Windows 服务、Linux systemd、Active-Active 多实例、WSL 原生编译）见
[`DEPLOY.md`](DEPLOY.md)；英文版见 [`README.en.md`](README.en.md) 与
[`DEPLOY.en.md`](DEPLOY.en.md)。

## 与 cep-engine 的对接契约

daemon 构造的 `RawEvent` JSON（字段名与 cep-engine `com.raysdata.cep.model.RawEvent`
严格一致）：

```json
{
  "source": "snmp_trap",
  "sourceIp": "192.0.2.10",
  "receivedAt": 1724400000000,
  "originTimestamp": 1724399999000,
  "rawEvent": "SNMP trap v2c from 192.0.2.10\n...",
  "metadata": {
    "trapOid": "1.3.6.1.6.3.1.1.5.3",
    "varbinds": {"ifIndex": "3", "ifDescr": "eth0"}
  }
}
```

要点：

- **`varbinds` 用字段名做 key**：与 cep-engine 生成 parser 的
  `varbinds.get(字段名)` 契约对齐。OID 无法映射到已知字段名时，保留原始完整
  实例 OID 作为 key（parser 的 `resolveInstanceOid` 支持完整实例 OID 兜底）。
- **`originTimestamp` 确定性**：由 trap 报文内的 `sysUpTime` 派生（v1/v2c 无设备
  绝对时间），保证同一设备同一 trap 在多个 Active-Active 实例生成的
  `originTimestamp` 一致，配合 cep-engine 指纹
  `source+sourceIp+SHA-256(rawEvent)+originTimestamp` 完成跨实例去重。
- **`rawEvent` 确定性文本**：不包含 `receivedAt`，可安全用于去重指纹。

## Active-Active 多实例部署

1. 部署 2 个及以上 trap-daemon 实例，均监听 UDP 162（可位于不同主机，或通过
   负载均衡/anycast 分发 trap）。
2. 所有实例配置指向**同一** cep-engine 与**同一** `oid-database.properties`。
3. 各实例独立转发同一 trap 到 cep-engine；cep-engine 的
   `TransportDeduplicator`（TTL 10s）自动丢弃重复事件。
4. 无需选主、无 failover 延迟；某实例宕机不影响其它实例收 trap。

## 自监控指标

Prometheus 抓取 `GET :9091/metrics`：

| 指标 | 类型 | 含义 |
|---|---|---|
| `trap_received_total` | counter | 累计收到 trap 数 |
| `trap_forward_total` | counter | 转发成功数 |
| `trap_forward_failed_total` | counter | 转发失败数 |
| `trap_dropped_total` | counter | 队列满丢弃数 |
| `queue_depth` | gauge | 当前队列深度 |
| `trapd_start_time_seconds` | gauge | 进程启动时间（unix） |
| `trap_throughput_5m` | gauge | last 5 min 平均吞吐（条/s，滑窗） |

查询 5 分钟吞吐：`rate(trap_received_total[5m])`，或直接读 `trap_throughput_5m`。

## 测试

```bash
go test ./...
```

单元测试覆盖 OID 前缀匹配、v1/v2c 解码、RawEvent 契约、批量队列背压与丢弃、
配置加载、指标。端到端集成测试用真实 gosnmp 报文验证
UDP → decode → oidmap → RawEvent → HTTP batch 全链路。

## 待办 / 预留

- SNMPv3 trap 支持（TrapDecoder 接口已预留）
- Kafka 转发通道（`kafka_forwarder.go` 已预留接口）
