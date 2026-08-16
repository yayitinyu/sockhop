# sockhop

通过导入 SOCKS5 / SOCKS5H 节点链接，把 Linux 主机的**全部 IPv4 出站流量**改由该节点转发，从而更改本机 V4 出口 IP。

- `sockhop-debian.sh` — Debian / Ubuntu（systemd、glibc、bash）
- `sockhop-alpine.sh` — Alpine（OpenRC、musl、busybox ash，纯 POSIX sh）

两个脚本命令行接口完全一致，差异只在包管理、服务系统和 DNS 实现。

---

## 原理

流量转发用 [tun2socks](https://github.com/xjasonlyu/tun2socks)（v2.7.0，静态 Go 二进制，glibc/musl 通用）。TCP 与 UDP 全覆盖，不是只处理 TCP 的 `iptables REDIRECT` 方案。

三重机制互锁：

| 机制 | 作用 |
|---|---|
| TUN 设备 + 独立路由表 | 未被豁免的 IPv4 包全部进入隧道，出口 IP 变为节点 IP |
| tun2socks `--fwmark` (SO_MARK) + `ip rule` | 它自己连代理的 socket 走物理网卡 —— **防止隧道自我循环** |
| conntrack 标记入站连接 | 回包原路返回物理网卡 —— **切换默认路由时 SSH 不断线** |

`main` 路由表**全程不修改**。所有改动集中在一张独立路由表（默认 520）加两条 `ip rule`，因此卸载是精确可逆的。

被豁免不走隧道的网段：回环、RFC1918 私网、CGNAT、链路本地（含 `169.254.169.254` 云元数据）、组播、保留段，以及代理服务器自身地址。

---

## 快速开始

在目标机器上直接拉取对应发行版的脚本：

```bash
# Debian / Ubuntu
curl -fsSL -o sockhop.sh https://raw.githubusercontent.com/yayitinyu/sockhop/main/sockhop-debian.sh
chmod +x sockhop.sh
sudo ./sockhop.sh start 'socks5://user:pass@1.2.3.4:1080'
```

```sh
# Alpine（最小系统通常没有 curl，先装上更稳；busybox wget 亦可）
apk add --no-cache curl
curl -fsSL -o sockhop.sh https://raw.githubusercontent.com/yayitinyu/sockhop/main/sockhop-alpine.sh
chmod +x sockhop.sh
./sockhop.sh start 'socks5://user:pass@1.2.3.4:1080'
```

首次运行会自动安装依赖（`iproute2 iptables curl unzip`）并下载 tun2socks 到 `/usr/local/bin/`。

### 装成常驻服务

`install` 会把脚本复制到 `/usr/local/bin/sockhop`、保存节点链接并注册开机自启，之后就能在任意目录直接用 `sockhop` 命令：

```bash
sudo ./sockhop.sh install 'socks5://user:pass@1.2.3.4:1080'

sudo systemctl start sockhop     # Debian / Ubuntu
rc-service sockhop start         # Alpine

sockhop status
```

`install` 只注册不启动，所以上面要单独 `start` 一次；此后开机自动拉起。

### 国内网络

tun2socks 从 GitHub Releases 下载。拉不动时换镜像前缀，或直接指定已有二进制：

```bash
sudo env SOCKHOP_MIRROR=https://ghproxy.example ./sockhop.sh start 'socks5://...'
sudo env SOCKHOP_BINARY=/root/tun2socks         ./sockhop.sh start 'socks5://...'
```

这里用 `sudo env`，是因为 `VAR=值 sudo ...` 会被 sudo 的 `env_reset` 吃掉（见上方提示）。

**动路由之前会先用 `curl --proxy` 预检节点。** 密码错或节点不通时直接报错退出，不会对系统做任何改动。

链接务必用**单引号**包裹，否则密码里的 `$` `!` 等会被 shell 吃掉。

### 支持的链接格式

```
socks5://user:pass@host:port          socks5h://user:pass@host:port
socks://<base64(user:pass)>@host:port      # v2rayN 分享格式
socks://<base64(user:pass@host:port)>
user:pass@host:port
host:port:user:pass                        # 多数代理商给的扁平格式
host:port                                  # 无认证
```

尾部 `#备注` 自动忽略；用户名密码支持 `%HH` 百分号编码；`socks5h` 归一化为 `socks5` —— TUN 模式下所有解析本来就走隧道，远程 DNS 语义天然满足。

---

## 命令

| 命令 | 说明 |
|---|---|
| `start [LINK]` | 启动。LINK 会保存到 `/etc/sockhop/config`（0600），之后可省略 |
| `stop` | 拆除全部改动，恢复原出口 |
| `restart [LINK]` | |
| `status` | 进程、设备、规则、当前出口 IP |
| `test` | 探测出口 IP 与 DNS |
| `install [LINK]` | 装到 `/usr/local/bin/sockhop` 并注册开机自启 |
| `uninstall` | 移除服务、配置与状态 |
| `logs [-f]` | 查看 tun2socks 日志 |

选项 `--dns tunnel|tcp|keep` 可加在任意位置，例如 `sockhop restart --dns tcp`。

开机自启：Debian 为 systemd unit（`systemctl start sockhop`），Alpine 为 OpenRC（`rc-service sockhop start`）。

## 环境变量

> **和 sudo 一起用时注意**：`SOCKHOP_DNS=tcp sudo ./sockhop.sh restart` **不生效**。变量是设给 sudo 进程的，而 sudo 默认 `env_reset` 会把它丢掉，脚本拿到的仍是默认值。写成 `sudo env VAR=值 ./sockhop.sh ...` 最稳妥。DNS 因此额外提供了 `--dns` 参数，不受此影响。

| 变量 | 默认 | 说明 |
|---|---|---|
| `SOCKHOP_DNS` | `tunnel` | `tunnel` / `tcp` / `keep`，见下节。等价于 `--dns` |
| `SOCKHOP_DNS_SERVERS` | `1.1.1.1 8.8.8.8` | |
| `SOCKHOP_BLOCK_V6` | `1` | 阻断 IPv6 出站防泄露 |
| `SOCKHOP_BYPASS` | — | 额外不走隧道的 CIDR，空格分隔 |
| `SOCKHOP_BINARY` | — | 用本地 tun2socks，不下载 |
| `SOCKHOP_MIRROR` | `https://github.com` | GitHub 下载前缀，国内可换镜像 |
| `SOCKHOP_TUN_NAME` / `SOCKHOP_MTU` / `SOCKHOP_FWMARK` / `SOCKHOP_TABLE` | `sockhop0` / `1500` / `4194304` / `520` | |

---

## DNS：最容易踩的坑

**多数 SOCKS5 节点不支持 UDP ASSOCIATE**，而 DNS 默认走 UDP。此时 TCP 流量正常但域名解析全挂。

`start` 结束时的自检会分别探测两者并明确区分这两种故障。看到 `DNS resolution through the tunnel failed` 就切 TCP 模式：

```bash
sudo ./sockhop.sh restart --dns tcp
```

两个发行版的 `tcp` 模式实现不同：

- **Debian/Ubuntu**：写入 glibc 的 `options use-vc`，解析器直接改用 TCP。
- **Alpine**：musl **没有** `use-vc` 等价选项，因此改为拉起一个仅监听 `127.0.0.1:53` 的私有 unbound，配置 `tcp-upstream: yes` 向上游转发。若 unbound 装不上或 53 端口被占，会告警并回退到 UDP 模式。

`keep` 模式完全不动 DNS —— 此时解析走本地/运营商 DNS，会暴露真实地理位置，仅在你明确需要内网解析时使用。

Debian 上若 systemd-resolved 在运行，脚本用 `resolvectl` 在 TUN 链路上设置解析器和 `~.` 路由域，不去动 `/etc/resolv.conf`。

---

## 安全与行为说明

**SSH 不会断。** 从物理网卡进入的连接会被 conntrack 打标，回包据此走回原路由。这是设计中最关键的一环。

**失败自动回滚。** 启动过程任何一步出错（包括中途 Ctrl-C），都会自动拆除已做的改动。自检不通过同样回滚。

**fail-closed。** tun2socks 若异常退出，路由仍指向 TUN，结果是断网而不是明文直连泄露真实 IP。这是有意的取舍——宁可断网也不泄露。`status` 会显示 `stale pidfile` 提示这种状态。

**IPv6 默认阻断。** 只改 V4 而放任 V6 的话，双栈站点会走原生 IPv6 直接暴露真实地址。脚本默认用 ip6tables 拒绝新的 IPv6 出站，但放行已建立连接（保住 IPv6 SSH）、链路本地与 ULA。`SOCKHOP_BLOCK_V6=0` 可关闭。

**rp_filter。** 严格模式会丢弃隧道回包，脚本把 TUN 设备设为 0、全局 strict 降为 loose，并保存原值在 `stop` 时还原。

**凭据。** 保存在 `/etc/sockhop/config`（0600，base64 包装，非加密）。日志 `/var/log/sockhop.log` 为 0600。终端输出中密码始终打码。

**如果本机是路由器**：转发流量同样会走隧道。不需要的话用 `SOCKHOP_BYPASS` 排除下游网段。

**容器**：需要 `--cap-add NET_ADMIN --device /dev/net/tun`。脚本会检测缺失并明确报错。

---

## 故障排查

| 现象 | 处理 |
|---|---|
| 出口 IP 没变 | `sockhop status` 看 tun2socks 是否在跑、规则是否存在 |
| TCP 通但域名解析失败 | 见上节，`sockhop restart --dns tcp` |
| `download failed` | 设 `SOCKHOP_MIRROR`，或用 `SOCKHOP_BINARY` 指向本地二进制 |
| `/dev/net/tun is missing` | 宿主 `modprobe tun`；容器补 `--device /dev/net/tun` |
| `'ip rule' is unavailable`（Alpine） | `apk add iproute2`，busybox 的 `ip` 不含策略路由 |
| 完全断网且脚本已失控 | 见下方手工清理 |

手工清理（幂等，可安全重复执行）：

```bash
ip rule del pref 9530; ip rule del pref 9520
ip route flush table 520
ip link del sockhop0
iptables -t mangle -D OUTPUT -j SOCKHOP_OUT
iptables -t mangle -D PREROUTING -j SOCKHOP_PRE
iptables -t mangle -F SOCKHOP_OUT; iptables -t mangle -X SOCKHOP_OUT
iptables -t mangle -F SOCKHOP_PRE; iptables -t mangle -X SOCKHOP_PRE
ip6tables -D OUTPUT -j SOCKHOP_V6; ip6tables -F SOCKHOP_V6; ip6tables -X SOCKHOP_V6
cp /var/lib/sockhop/resolv.conf.bak /etc/resolv.conf
```

---

## 验证状态

已执行并通过：

- 语法检查 —— `bash -n`（Debian 版）、`dash -n` 与 `sh -n`（Alpine 版）
- 链接解析 —— 两版各 14 个用例，含全部 6 种格式、base64、百分号编码、密码内含裸 `@` 和 `/`、大小写 scheme、`#备注`，以及 4 个必须被拒绝的非法输入；两版输出逐条一致
- `set -e` 健壮性 —— mock 网络命令后跑通 14 项回滚/探测路径，确认无意外退出（这类脚本最常见的隐患是 `[ cond ] && cmd` 在条件为假时触发 `set -e`）
- 配置持久化 —— 含特殊字符密码的 round-trip 一致，文件权限 0600
- tun2socks 的命令行参数、`socks5` scheme 注册、`--fwmark` 的 SO_MARK 语义、release 资产命名 —— 均对照上游 v2.7.0 源码与 GitHub API 逐项核对，非凭记忆

**未执行**：端到端实跑。这需要 Linux root 环境和一个真实 SOCKS5 节点，当前开发环境（Windows）无法提供。路由与 iptables 的行为是静态推演的，四条路径（入站 SSH 回包、tun2socks 到代理、本机普通出站、隧道回程）逐一核对过，但**未在真机上观测**。

建议首次使用时留一个带外访问通道（云厂商 VNC / 串口控制台）作为兜底。
