# traffic-analyzer

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
traffic-analyzer/
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
5. 默认 DB 路径为 `/var/lib/traffic-analyzer/traffic-analyzer.db`，程序会自动创建父目录。

## 快速开始

最简单用法（默认 DB 路径已内置）：

```bash
sudo ./target/release/traffic-analyzer run --iface eth0
```

如果你还没编译过，直接一条命令完成构建并启动：

```bash
./hack/build-single.sh && sudo ./target/release/traffic-analyzer run --iface eth0
```

采集启动后，另开一个终端看实时面板：

```bash
./target/release/traffic-analyzer ui --iface eth0
```

详细命令（构建、run 参数、全部 top-* / 诊断命令）见：
`docs/USAGE.md`

## 持久化策略

1. 聚合周期：默认每 `1s` 采集 flow map 增量并触发一次聚合/落库。
2. 事件拉取：默认每 `100ms` 高频拉取 DNS/TLS ringbuf（`--event-poll-millis` 可调），降低突发丢事件。
3. 聚合粒度：按分钟键（`ts_minute`）聚合到 `flow_1m_5t` 与 `dns_1m`。
4. 写入模式：采集线程异步投递批次，后台写线程执行 SQLite `WAL` + 事务 `upsert`。
5. 保留策略：通过 `prune` 命令保留最近 N 天数据。
6. 退出行为：默认支持 `Ctrl+C` 优雅退出，退出前会执行最终一次增量采集并等待写线程完成落库。
7. 新增表：`sni_1m`（SNI 计数）和 `dns_cache_1m`（缓存行为指标）。
8. 流量表使用五元组：`flow_1m_5t` 记录 `src_ip/src_port/dst_ip/dst_port/proto/direction/domain/bytes/packets`。
9. 兼容迁移：启动时会自动检测旧版 `flow_1m(peer_ip/peer_port)` 表并一次性迁移到 `flow_1m_5t`，迁移状态保存在 `meta_kv`。
10. 查询连接策略：查询命令优先使用可写连接（便于自动建表/迁移），若命中只读错误会自动降级为只读连接。

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
