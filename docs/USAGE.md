# Usage Guide

本文档提供完整的构建、采集、查询命令。  
如果只想快速跑起来，请看 `README.md` 的“快速开始”。

## 构建

说明：
1. `bpfel-unknown-none` 是 `no_std` 目标，当前 Rust stable 不能直接 `rustup target add bpfel-unknown-none`。
2. eBPF 需要 `nightly + -Z build-std=core`。
3. eBPF 链接需要 `bpf-linker`，`./hack/build-ebpf.sh` 会自动检查并安装。

```bash
cd /path/to/traffic-analyzer

# 用户态
cargo build -p traffic-analyzer --release

# eBPF（推荐，脚本会安装 nightly + rust-src 并使用 build-std）
./hack/build-ebpf.sh --release

# 单二进制打包（内嵌 eBPF）
./hack/build-single.sh
```

手动构建 eBPF 的等价命令：

```bash
rustup toolchain install nightly --component rust-src
cargo install bpf-linker
cargo +nightly build -Z build-std=core --target bpfel-unknown-none -p traffic-analyzer-ebpf --release
# eBPF object path:
# ./target/bpfel-unknown-none/release/libtraffic_analyzer_ebpf.so
```

## 采集（run）

完整参数示例：

```bash
cargo run -p traffic-analyzer -- run \
  --iface eth0 \
  --bpf-object ./target/bpfel-unknown-none/release/libtraffic_analyzer_ebpf.so \
  --db /var/lib/traffic-analyzer/traffic-analyzer.db \
  --flush-interval-secs 1 \
  --event-poll-millis 100 \
  --dns-ttl-cap-secs 600 \
  --sni-ttl-cap-secs 300 \
  --flow-idle-timeout-secs 900
```

最小参数（自动探测 eBPF 产物，失败则回退到内嵌对象）：

```bash
cargo run -p traffic-analyzer -- run --iface eth0
```

单二进制模式：

```bash
sudo ./target/release/traffic-analyzer run --iface eth0 --db /var/lib/traffic-analyzer/traffic-analyzer.db
```

eBPF 加载优先级：
1. 显式 `--bpf-object`。
2. 自动探测本地构建产物路径。
3. 编译期内嵌对象（`./hack/build-single.sh` 构建时生效）。

## 报表命令

```bash
# Top IP
cargo run -p traffic-analyzer -- top-ip --iface eth0 --db /var/lib/traffic-analyzer/traffic-analyzer.db --lookback-minutes 60 --limit 20

# Top LAN IP（内网设备维度）
cargo run -p traffic-analyzer -- top-lan --iface eth0 --db /var/lib/traffic-analyzer/traffic-analyzer.db --lookback-minutes 60 --limit 20

# Top 5-tuple Flow（src_ip:src_port -> dst_ip:dst_port）
cargo run -p traffic-analyzer -- top-flow --iface eth0 --db /var/lib/traffic-analyzer/traffic-analyzer.db --lookback-minutes 60 --limit 20

# Top Domain
cargo run -p traffic-analyzer -- top-domain --iface eth0 --db /var/lib/traffic-analyzer/traffic-analyzer.db --lookback-minutes 60 --limit 20

# Top DNS Query
cargo run -p traffic-analyzer -- top-dns --iface eth0 --db /var/lib/traffic-analyzer/traffic-analyzer.db --lookback-minutes 60 --limit 20

# Top TLS SNI
cargo run -p traffic-analyzer -- top-sni --iface eth0 --db /var/lib/traffic-analyzer/traffic-analyzer.db --lookback-minutes 60 --limit 20

# Top QUIC(udp/443)
cargo run -p traffic-analyzer -- top-quic --iface eth0 --db /var/lib/traffic-analyzer/traffic-analyzer.db --lookback-minutes 60 --limit 20

# 单域名流量明细（按 direction/proto/port）
cargo run -p traffic-analyzer -- domain-detail --iface eth0 --db /var/lib/traffic-analyzer/traffic-analyzer.db --domain api.github.com --lookback-minutes 60 --limit 50

# 归因覆盖率（exact/unknown）
cargo run -p traffic-analyzer -- attribution-coverage --iface eth0 --db /var/lib/traffic-analyzer/traffic-analyzer.db --lookback-minutes 60

# DNS/SNI 缓存行为
cargo run -p traffic-analyzer -- dns-cache-inspect --iface eth0 --db /var/lib/traffic-analyzer/traffic-analyzer.db --lookback-minutes 60 --limit 20

# 采集健康度（flow map 压力 / 丢事件）
cargo run -p traffic-analyzer -- collector-health --iface eth0 --db /var/lib/traffic-analyzer/traffic-analyzer.db --lookback-minutes 60 --limit 20

# 可疑 DoH/DoT
cargo run -p traffic-analyzer -- top-dohdot --iface eth0 --db /var/lib/traffic-analyzer/traffic-analyzer.db --lookback-minutes 60 --limit 20

# 实时面板（3 个页面，Tab/Shift+Tab 或 Left/Right 切换，q 退出）
cargo run -p traffic-analyzer -- ui --iface eth0 --db /var/lib/traffic-analyzer/traffic-analyzer.db --lookback-minutes 60 --limit 10 --refresh-secs 2

# 清理 30 天前数据
cargo run -p traffic-analyzer -- prune --db /var/lib/traffic-analyzer/traffic-analyzer.db --retention-days 30
```
