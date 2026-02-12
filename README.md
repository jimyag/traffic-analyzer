# traffic-analyzer-rs

基于 Rust + aya 的家庭网络流量分析工具，目标是回答“流量花在哪里”。

## 功能

1. 指定网卡 `ingress/egress` 流量统计（按 `IP/proto/port` 聚合）。
2. 通过 eBPF `RingBuf` 上报 DNS 报文片段，在 userspace 解析 `qname` 并统计查询次数。
3. 在 userspace 解析 DNS 响应并维护 `ip -> domain` TTL 映射，将流量归因到域名。
4. 持久化到 SQLite（WAL），支持 `Top IP / Top LAN IP / Top Domain / Top DNS` 查询。
5. 支持 `Top SNI / Domain Detail / Attribution Coverage / DNS Cache Inspect / DoHDoT` 查询。
6. 支持采集健康度观测（`collector-health`）：flow map 占用、老化回收、ringbuf 丢事件。
7. 支持历史数据清理（`prune`）。

## 目录结构

```text
traffic-analyzer-rs/
├── Cargo.toml                    # workspace
├── README.md
├── traffic-analyzer-common/      # eBPF 与 userspace 共享结构
├── traffic-analyzer-ebpf/        # tc ingress/egress eBPF 程序
└── traffic-analyzer/             # userspace CLI + SQLite 聚合
```

## 运行前提

1. Linux 内核支持 eBPF + tc `clsact`。
2. 运行用户具备 root 或等效权限。
3. 建议关闭或减少 DNS over HTTPS / DNS over TLS，否则域名归因会下降。
4. 若 DB 文件由 `sudo` 生成，首次查询建议使用可写权限运行一次（或调整文件属主），以完成自动建表/迁移。

## 构建

> 说明：`bpfel-unknown-none` 是 `no_std` 目标，当前 Rust stable 不能用 `rustup target add bpfel-unknown-none` 直接安装预编译标准库。  
> 需要使用 `nightly + -Z build-std=core` 方式构建 eBPF。
> eBPF 链接需要 `bpf-linker`，`./hack/build-ebpf.sh` 会自动检查并安装。

```bash
cd cmd/tools/traffic-analyzer-rs

# 用户态
cargo build -p traffic-analyzer --release

# eBPF（推荐，脚本会安装 nightly + rust-src 并使用 build-std）
./hack/build-ebpf.sh --release

# 单二进制打包（内嵌 eBPF）
./hack/build-single.sh
```

## 采集命令

```bash
cd cmd/tools/traffic-analyzer-rs

cargo run -p traffic-analyzer -- run \
  --iface eth0 \
  --bpf-object ./target/bpfel-unknown-none/release/traffic-analyzer-ebpf \
  --db ./traffic-analyzer.db \
  --flush-interval-secs 1 \
  --dns-ttl-cap-secs 600 \
  --sni-ttl-cap-secs 300 \
  --flow-idle-timeout-secs 900

# 或者省略 --bpf-object，程序会自动探测常见构建产物路径
cargo run -p traffic-analyzer -- run --iface eth0
```

单二进制模式下，`traffic-analyzer` 会在编译期内嵌 eBPF 对象，运行时可不传 `--bpf-object`：

```bash
sudo ./target/release/traffic-analyzer run --iface eth0 --db ./traffic-analyzer.db
```

eBPF 加载优先级：

1. 显式 `--bpf-object`。
2. 自动探测本地构建产物路径。
3. 编译期内嵌对象（通过 `./hack/build-single.sh` 构建时生效）。

如果你手动构建 eBPF，等价命令是：

```bash
rustup toolchain install nightly --component rust-src
cargo install bpf-linker
cargo +nightly build -Z build-std=core --target bpfel-unknown-none -p traffic-analyzer-ebpf --release
```

## 报表命令

```bash
# Top IP
cargo run -p traffic-analyzer -- top-ip --iface eth0 --db ./traffic-analyzer.db --lookback-minutes 60 --limit 20

# Top LAN IP（内网设备维度）
cargo run -p traffic-analyzer -- top-lan --iface eth0 --db ./traffic-analyzer.db --lookback-minutes 60 --limit 20

# Top 5-tuple Flow（src_ip:src_port -> dst_ip:dst_port）
cargo run -p traffic-analyzer -- top-flow --iface eth0 --db ./traffic-analyzer.db --lookback-minutes 60 --limit 20

# Top Domain
cargo run -p traffic-analyzer -- top-domain --iface eth0 --db ./traffic-analyzer.db --lookback-minutes 60 --limit 20

# Top DNS Query
cargo run -p traffic-analyzer -- top-dns --iface eth0 --db ./traffic-analyzer.db --lookback-minutes 60 --limit 20

# Top TLS SNI
cargo run -p traffic-analyzer -- top-sni --iface eth0 --db ./traffic-analyzer.db --lookback-minutes 60 --limit 20

# Top QUIC(udp/443)
cargo run -p traffic-analyzer -- top-quic --iface eth0 --db ./traffic-analyzer.db --lookback-minutes 60 --limit 20

# 单域名流量明细（按 direction/proto/port）
cargo run -p traffic-analyzer -- domain-detail --iface eth0 --db ./traffic-analyzer.db --domain api.github.com --lookback-minutes 60 --limit 50

# 归因覆盖率（exact/unknown）
cargo run -p traffic-analyzer -- attribution-coverage --iface eth0 --db ./traffic-analyzer.db --lookback-minutes 60

# DNS/SNI 缓存行为
cargo run -p traffic-analyzer -- dns-cache-inspect --iface eth0 --db ./traffic-analyzer.db --lookback-minutes 60 --limit 20

# 采集健康度（flow map 压力 / 丢事件）
cargo run -p traffic-analyzer -- collector-health --iface eth0 --db ./traffic-analyzer.db --lookback-minutes 60 --limit 20

# 可疑 DoH/DoT
cargo run -p traffic-analyzer -- top-dohdot --iface eth0 --db ./traffic-analyzer.db --lookback-minutes 60 --limit 20

# 实时面板（统一查看 Top Domain/IP/LAN IP/DNS/SNI/QUIC/DoH/DoT/Coverage）
cargo run -p traffic-analyzer -- ui --iface eth0 --db ./traffic-analyzer.db --lookback-minutes 60 --limit 10 --refresh-secs 2

# 清理 30 天前数据
cargo run -p traffic-analyzer -- prune --db ./traffic-analyzer.db --retention-days 30
```

## 持久化策略

1. 采集周期：默认每 `1s` 拉取 map/ringbuf 增量。
2. 聚合粒度：按分钟键（`ts_minute`）聚合到 `flow_1m_5t` 与 `dns_1m`。
3. 写入模式：采集线程异步投递批次，后台写线程执行 SQLite `WAL` + 事务 `upsert`。
4. 保留策略：通过 `prune` 命令保留最近 N 天数据。
5. 退出行为：默认支持 `Ctrl+C` 优雅退出，退出前会执行最终一次增量采集并等待写线程完成落库。
6. 新增表：`sni_1m`（SNI 计数）和 `dns_cache_1m`（缓存行为指标）。
7. 流量表使用五元组：`flow_1m_5t` 记录 `src_ip/src_port/dst_ip/dst_port/proto/direction/domain/bytes/packets`。
8. 兼容迁移：启动时会自动检测旧版 `flow_1m(peer_ip/peer_port)` 表并一次性迁移到 `flow_1m_5t`，迁移状态保存在 `meta_kv`。
9. 查询连接策略：查询命令优先使用可写连接（便于自动建表/迁移），若命中只读错误会自动降级为只读连接。

## DNS 实现说明

1. eBPF 程序仅做轻量工作：识别 DNS UDP 包、上报 `DnsEvent`，并持续维护 `FLOW_STATS`。
2. DNS 解析全部在 userspace 完成：包括 query 提取、answer 解析（A/AAAA）和 TTL 处理。
3. 为兼顾 verifier 稳定性和开销，eBPF 采用分档固定长度抓取（`12/16/24/32/48/64/96` 字节）。
4. 若 `captured_len` 不足以覆盖完整 DNS 名称或答案，当前条目会被跳过，不会写入错误域名。
5. SNI 解析为 best-effort：仅解析 TLS ClientHello 中明文 SNI，受抓包截断、连接复用和 ECH 影响。

## 精度与边界

1. 域名归因是近似值，`CDN` 共享 IP 会产生歧义。
2. `DoH/DoT` 场景下无法直接看到明文 `qname`。
3. 当前支持 IPv4/IPv6 基础 L3/L4 解析；复杂 IPv6 扩展头场景仍可能漏计。
4. 当前实现优先稳定和低开销，未做进程级归因。
5. `top-dohdot` 为可疑流量识别：DoH 基于已知解析器域名列表，DoT 基于 `853` 端口统计。
6. `top-ip` 统计的是“对端 IP”（ingress 用 `src_ip`，egress 用 `dst_ip`）；`top-lan` 统计的是“本机/内网侧 IP”（ingress 用 `dst_ip`，egress 用 `src_ip`）。

## 后续建议

1. 增加 `exact/ambiguous/unknown` 更细粒度归因标签。
2. 增加设备维度（内网 IP/MAC）日榜。
3. 输出 Prometheus 指标与 Grafana 大盘。
4. 新增 `1h` 聚合表，降低长期存储体积。
