#!/usr/bin/env bash
#
# sockhop - route all IPv4 egress traffic of this host through a SOCKS5 proxy.
# Target: Debian / Ubuntu (systemd, glibc, bash).
#
# How it works
# ------------
#   1. A TUN device is created and given a default route inside a dedicated
#      routing table. Every IPv4 packet that is not explicitly bypassed enters
#      it, so the host's egress address becomes the proxy's address.
#   2. tun2socks reads that device and re-dials each flow over SOCKS5.
#   3. tun2socks' own proxy-facing sockets carry SO_MARK (--fwmark). A policy
#      rule sends marked packets to the main table, so they leave via the
#      physical link. Without this the tunnel would feed itself - a hard loop.
#   4. Connections that arrive from outside are conntrack-marked, and their
#      replies inherit that mark. This is what keeps an in-flight SSH session
#      alive while the default route is being swapped underneath it.
#
# The main routing table is never modified: everything lives in a separate
# table plus two `ip rule` entries, which makes teardown exact and reversible.
#
# Requires: root, /dev/net/tun, iproute2, iptables, curl, unzip.

set -euo pipefail

APP="sockhop"
CONF_DIR="/etc/sockhop"
CONF_FILE="${CONF_DIR}/config"
STATE_DIR="/var/lib/sockhop"
RUN_DIR="/run/sockhop"
PID_FILE="${RUN_DIR}/tun2socks.pid"
LOG_FILE="/var/log/sockhop.log"
T2S_BIN="/usr/local/bin/tun2socks"
SELF_BIN="/usr/local/bin/sockhop"
SERVICE_FILE="/etc/systemd/system/sockhop.service"
RESOLV_BACKUP="${STATE_DIR}/resolv.conf.bak"

# Tunables (override via environment).
TUN_NAME="${SOCKHOP_TUN_NAME:-sockhop0}"
TUN_ADDR="${SOCKHOP_TUN_ADDR:-198.18.0.1}"      # RFC 2544 benchmark range
TUN_PREFIX="${SOCKHOP_TUN_PREFIX:-15}"
TUN_MTU="${SOCKHOP_MTU:-1500}"
FWMARK_DEC="${SOCKHOP_FWMARK:-4194304}"         # 0x400000, a bit nobody else uses
RT_TABLE="${SOCKHOP_TABLE:-520}"
PREF_BYPASS="${SOCKHOP_PREF_BYPASS:-9520}"
PREF_TUN="${SOCKHOP_PREF_TUN:-9530}"
DNS_MODE="${SOCKHOP_DNS:-tunnel}"               # tunnel | tcp | keep
DNS_SERVERS="${SOCKHOP_DNS_SERVERS:-1.1.1.1 8.8.8.8}"
BLOCK_V6="${SOCKHOP_BLOCK_V6:-1}"
BYPASS_EXTRA="${SOCKHOP_BYPASS:-}"
T2S_VERSION="${SOCKHOP_T2S_VERSION:-v2.7.0}"
T2S_MIRROR="${SOCKHOP_MIRROR:-https://github.com}"
LOGLEVEL="${SOCKHOP_LOGLEVEL:-info}"

CHAIN_OUT="SOCKHOP_OUT"
CHAIN_PRE="SOCKHOP_PRE"
CHAIN_V6="SOCKHOP_V6"

# Never tunnel these: loopback, RFC1918, CGNAT, link-local (incl. cloud
# metadata at 169.254.169.254), multicast and reserved space.
BYPASS_V4="0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 224.0.0.0/4 240.0.0.0/4"

FWMARK_HEX="$(printf '0x%x' "$FWMARK_DEC")"

WAN_IF=""; WAN_GW=""
P_HOST=""; P_PORT=""; P_USER=""; P_PASS=""; P_URL=""
STARTED=0

# --------------------------------------------------------------------------
# Output helpers
# --------------------------------------------------------------------------

if [[ -t 1 ]]; then
    C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'
    C_CYA=$'\033[36m'; C_DIM=$'\033[2m';  C_RST=$'\033[0m'
else
    C_RED=""; C_GRN=""; C_YEL=""; C_CYA=""; C_DIM=""; C_RST=""
fi

info() { printf '%s[*]%s %s\n' "$C_CYA" "$C_RST" "$*"; }
ok()   { printf '%s[+]%s %s\n' "$C_GRN" "$C_RST" "$*"; }
warn() { printf '%s[!]%s %s\n' "$C_YEL" "$C_RST" "$*" >&2; }
die()  { printf '%s[x]%s %s\n' "$C_RED" "$C_RST" "$*" >&2; exit 1; }

require_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        die "must run as root"
    fi
}

have() { command -v "$1" >/dev/null 2>&1; }

# --------------------------------------------------------------------------
# Node link parsing
# --------------------------------------------------------------------------

# Only %HH sequences are turned into escapes, so a stray '%' in a hand-written
# password cannot corrupt the rest of the string.
urldecode() {
    local s
    s="$(printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/%\([0-9a-fA-F][0-9a-fA-F]\)/\\x\1/g')"
    printf '%b' "$s"
}

# Escape only what actually breaks a URL userinfo field. '%' must go first.
urlencode() {
    printf '%s' "$1" | sed -e 's/%/%25/g' -e 's/:/%3A/g' -e 's/@/%40/g' \
        -e 's|/|%2F|g' -e 's/?/%3F/g' -e 's/#/%23/g' \
        -e 's/\[/%5B/g' -e 's/\]/%5D/g' -e 's/ /%20/g'
}

b64d() {
    local s
    s="$(printf '%s' "$1" | tr -- '-_' '+/')"
    case $(( ${#s} % 4 )) in
        2) s="${s}==" ;;
        3) s="${s}=" ;;
        1) return 1 ;;
    esac
    printf '%s' "$s" | base64 -d 2>/dev/null
}

is_port() {
    [[ "$1" =~ ^[0-9]+$ ]] && [[ "$1" -ge 1 ]] && [[ "$1" -le 65535 ]]
}

split_hostport() {
    local hp="$1"
    if [[ "$hp" == \[*\]:* ]]; then          # bracketed IPv6 literal
        P_HOST="${hp%%\]:*}"; P_HOST="${P_HOST#\[}"
        P_PORT="${hp##*\]:}"
    elif [[ "$hp" == *:* ]]; then
        P_HOST="${hp%:*}"
        P_PORT="${hp##*:}"
    else
        die "link is missing a port: $hp"
    fi
    if [[ -z "$P_HOST" ]]; then
        die "link has an empty host"
    fi
    if ! is_port "$P_PORT"; then
        die "invalid port in link: $P_PORT"
    fi
}

# Normalise every accepted link format into socks5://[user:pass@]host:port.
# tun2socks only registers the "socks5" scheme; socks5h differs solely in who
# resolves names, and under a TUN every lookup already travels the tunnel, so
# folding 5h into 5 preserves the remote-DNS semantics.
parse_link() {
    local raw="$1" depth="${2:-0}" scheme body userinfo hostport decoded fields

    if [[ "$depth" -ge 3 ]]; then
        die "link is nested too deeply"
    fi

    raw="$(printf '%s' "$raw" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's/#.*$//')"
    if [[ -z "$raw" ]]; then
        die "empty link"
    fi

    if [[ "$raw" == *"://"* ]]; then
        scheme="${raw%%://*}"
        scheme="${scheme,,}"
        body="${raw#*://}"
        case "$scheme" in
            socks5|socks5h|socks|socks5t) : ;;
            *) die "unsupported scheme '${scheme}': only socks5/socks5h/socks are accepted" ;;
        esac
    else
        body="$raw"
    fi
    body="${body%/}"
    if [[ -z "$body" ]]; then
        die "link has no body"
    fi

    if [[ "$body" != *"@"* ]]; then
        # host:port:user:pass - the flat form most proxy vendors hand out.
        fields="$(printf '%s' "$body" | awk -F: '{print NF}')"
        if [[ "$fields" -eq 4 ]]; then
            IFS=: read -r P_HOST P_PORT P_USER P_PASS <<<"$body"
            if ! is_port "$P_PORT"; then
                die "invalid port in link: $P_PORT"
            fi
            build_url
            return 0
        fi
        # Whole payload base64-encoded (socks://<base64 of user:pass@host:port>).
        if [[ "$body" != *:* ]]; then
            decoded="$(b64d "$body")" || die "link is neither host:port nor valid base64"
            if [[ -z "$decoded" ]]; then
                die "base64 payload decoded to nothing"
            fi
            parse_link "socks5://${decoded}" $((depth + 1))
            return 0
        fi
    fi

    if [[ "$body" == *"@"* ]]; then
        userinfo="${body%@*}"                    # last @ splits creds from host
        hostport="${body##*@}"
        if [[ "$userinfo" == *:* ]]; then
            P_USER="$(urldecode "${userinfo%%:*}")"
            P_PASS="$(urldecode "${userinfo#*:}")"
        else
            # v2rayN-style socks://<base64(user:pass)>@host:port
            decoded="$(b64d "$userinfo")" || die "cannot decode credentials in link"
            if [[ "$decoded" != *:* ]]; then
                die "decoded credentials are not user:pass"
            fi
            P_USER="${decoded%%:*}"
            P_PASS="${decoded#*:}"
        fi
    else
        hostport="$body"
    fi

    split_hostport "$hostport"
    build_url
}

build_url() {
    if [[ -n "$P_USER" ]]; then
        P_URL="socks5://$(urlencode "$P_USER"):$(urlencode "$P_PASS")@${P_HOST}:${P_PORT}"
    else
        P_URL="socks5://${P_HOST}:${P_PORT}"
    fi
}

redact_url() {
    if [[ -n "$P_USER" ]]; then
        printf 'socks5://%s:****@%s:%s' "$P_USER" "$P_HOST" "$P_PORT"
    else
        printf 'socks5://%s:%s' "$P_HOST" "$P_PORT"
    fi
}

save_config() {
    local enc
    mkdir -p "$CONF_DIR"
    enc="$(printf '%s' "$P_URL" | base64 | tr -d '\n')"
    umask 077
    {
        printf '# Managed by %s. Contains proxy credentials - keep mode 0600.\n' "$APP"
        printf 'SOCKHOP_LINK_B64=%s\n' "$enc"
        printf 'SOCKHOP_HOST=%s\n' "$P_HOST"
        printf 'SOCKHOP_PORT=%s\n' "$P_PORT"
    } >"$CONF_FILE"
    chmod 600 "$CONF_FILE"
}

load_config() {
    local b64
    if [[ ! -r "$CONF_FILE" ]]; then
        return 1
    fi
    b64="$(sed -n 's/^SOCKHOP_LINK_B64=//p' "$CONF_FILE" | head -n1)"
    if [[ -z "$b64" ]]; then
        return 1
    fi
    parse_link "$(printf '%s' "$b64" | base64 -d)"
}

# --------------------------------------------------------------------------
# Environment discovery
# --------------------------------------------------------------------------

# Resolve the uplink through the bypass mark, so this reports the physical
# link even when the tunnel is already up and owns the unmarked default route.
detect_uplink() {
    local line
    line="$(ip -4 route get 1.1.1.1 mark "$FWMARK_HEX" 2>/dev/null | head -n1 || true)"
    if [[ -z "$line" ]]; then
        line="$(ip -4 route show default 2>/dev/null | head -n1 || true)"
    fi
    if [[ -z "$line" ]]; then
        die "no IPv4 default route; cannot determine the uplink"
    fi

    WAN_IF="$(printf '%s' "$line" | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
    WAN_GW="$(printf '%s' "$line" | awk '{for(i=1;i<=NF;i++) if($i=="via"){print $(i+1); exit}}')"
    if [[ -z "$WAN_IF" ]]; then
        die "could not parse the uplink interface from: $line"
    fi
    if [[ "$WAN_IF" == "$TUN_NAME" ]]; then
        die "uplink resolves to $TUN_NAME; run '$APP stop' first"
    fi
}

detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)   echo "amd64"   ;;
        aarch64|arm64)  echo "arm64"   ;;
        armv7l|armv7)   echo "armv7"   ;;
        armv6l)         echo "armv6"   ;;
        armv5*)         echo "armv5"   ;;
        i386|i686)      echo "386"     ;;
        riscv64)        echo "riscv64" ;;
        *) die "unsupported architecture: $(uname -m)" ;;
    esac
}

ensure_deps() {
    local missing=()
    have ip       || missing+=("iproute2")
    have iptables || missing+=("iptables")
    have curl     || missing+=("curl")
    have unzip    || missing+=("unzip")

    if [[ ${#missing[@]} -gt 0 ]]; then
        info "installing: ${missing[*]}"
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq || warn "apt-get update failed; trying to install anyway"
        apt-get install -y -qq --no-install-recommends "${missing[@]}" \
            || die "failed to install: ${missing[*]}"
    fi

    if [[ ! -c /dev/net/tun ]]; then
        modprobe tun 2>/dev/null || true
        if [[ ! -c /dev/net/tun ]]; then
            die "/dev/net/tun is missing. On a container, pass --device /dev/net/tun --cap-add NET_ADMIN."
        fi
    fi

    iptables -t mangle -L >/dev/null 2>&1 \
        || die "iptables cannot reach the mangle table - missing kernel modules or NET_ADMIN"
}

ensure_binary() {
    local arch url tmp extracted

    if [[ -n "${SOCKHOP_BINARY:-}" ]]; then
        if [[ ! -x "$SOCKHOP_BINARY" ]]; then
            die "SOCKHOP_BINARY is not executable: $SOCKHOP_BINARY"
        fi
        install -m 0755 "$SOCKHOP_BINARY" "$T2S_BIN"
        return 0
    fi
    if [[ -x "$T2S_BIN" ]]; then
        return 0
    fi

    arch="$(detect_arch)"
    url="${T2S_MIRROR}/xjasonlyu/tun2socks/releases/download/${T2S_VERSION}/tun2socks-linux-${arch}.zip"
    tmp="$(mktemp -d)"

    info "downloading tun2socks ${T2S_VERSION} (${arch})"
    if ! curl -fsSL --retry 3 --connect-timeout 15 -o "${tmp}/t2s.zip" "$url"; then
        rm -rf "$tmp"
        die "download failed: $url (set SOCKHOP_MIRROR or SOCKHOP_BINARY)"
    fi
    if ! unzip -oq "${tmp}/t2s.zip" -d "$tmp"; then
        rm -rf "$tmp"
        die "failed to unpack the archive"
    fi

    extracted="$(find "$tmp" -type f -name 'tun2socks*' ! -name '*.zip' | head -n1)"
    if [[ -z "$extracted" ]]; then
        rm -rf "$tmp"
        die "no tun2socks binary inside the archive"
    fi
    install -m 0755 "$extracted" "$T2S_BIN"
    rm -rf "$tmp"

    "$T2S_BIN" --version >/dev/null 2>&1 || die "the downloaded binary does not run on this host"
    ok "installed $T2S_BIN"
}

# --------------------------------------------------------------------------
# Network plumbing
# --------------------------------------------------------------------------

# rp_filter in strict mode drops the proxy's reply packets, because their
# source addresses are only reachable through the tunnel table rather than
# main. Relax it for the TUN device and downgrade a strict global setting to
# loose, saving the old value so stop() can put it back.
tune_rp_filter() {
    local all="/proc/sys/net/ipv4/conf/all/rp_filter"
    local dev="/proc/sys/net/ipv4/conf/${TUN_NAME}/rp_filter"
    local now

    mkdir -p "$STATE_DIR"
    if [[ -r "$all" ]]; then
        now="$(cat "$all" 2>/dev/null || echo 0)"
        printf '%s\n' "$now" >"${STATE_DIR}/rp_filter.all"
        if [[ "$now" == "1" ]]; then
            printf '2\n' >"$all" 2>/dev/null || true
        fi
    fi
    if [[ -w "$dev" ]]; then
        printf '0\n' >"$dev" 2>/dev/null || true
    fi
    return 0
}

restore_rp_filter() {
    local file="${STATE_DIR}/rp_filter.all"
    local all="/proc/sys/net/ipv4/conf/all/rp_filter"
    local saved
    if [[ -r "$file" && -w "$all" ]]; then
        saved="$(cat "$file")"
        if [[ -n "$saved" ]]; then
            printf '%s\n' "$saved" >"$all" 2>/dev/null || true
        fi
    fi
    rm -f "$file"
    return 0
}

resolve_host() {
    getent ahostsv4 "$1" 2>/dev/null | awk '{print $1}' | sort -u || true
}

setup_routing() {
    local cidr addr

    ip addr replace "${TUN_ADDR}/${TUN_PREFIX}" dev "$TUN_NAME"
    ip link set dev "$TUN_NAME" up
    ip link set dev "$TUN_NAME" mtu "$TUN_MTU" 2>/dev/null || true
    tune_rp_filter

    ip route flush table "$RT_TABLE" 2>/dev/null || true
    ip route add default dev "$TUN_NAME" table "$RT_TABLE"

    # `throw` ends the lookup in this table and lets the kernel fall through to
    # the next rule (main), so bypassed destinations keep their normal path
    # even if the gateway changes later.
    for cidr in $BYPASS_V4 $BYPASS_EXTRA; do
        ip route add throw "$cidr" table "$RT_TABLE" 2>/dev/null || true
    done
    # Belt and braces alongside the fwmark rule: keep the proxy itself direct.
    if [[ "$P_HOST" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        ip route add throw "${P_HOST}/32" table "$RT_TABLE" 2>/dev/null || true
    else
        for addr in $(resolve_host "$P_HOST"); do
            ip route add throw "${addr}/32" table "$RT_TABLE" 2>/dev/null || true
        done
    fi

    while ip rule del pref "$PREF_BYPASS" 2>/dev/null; do :; done
    while ip rule del pref "$PREF_TUN"    2>/dev/null; do :; done
    ip rule add pref "$PREF_BYPASS" fwmark "${FWMARK_HEX}/${FWMARK_HEX}" lookup main
    ip rule add pref "$PREF_TUN" lookup "$RT_TABLE"
    ip route flush cache 2>/dev/null || true
}

setup_iptables() {
    iptables -t mangle -N "$CHAIN_OUT" 2>/dev/null || iptables -t mangle -F "$CHAIN_OUT"
    iptables -t mangle -N "$CHAIN_PRE" 2>/dev/null || iptables -t mangle -F "$CHAIN_PRE"

    # Inbound connections are tagged on arrival...
    iptables -t mangle -A "$CHAIN_PRE" -i "$WAN_IF" -m conntrack --ctstate NEW \
        -j CONNMARK --set-xmark "${FWMARK_HEX}/${FWMARK_HEX}"

    # ...tun2socks' own SO_MARK is copied into the conntrack entry on the first
    # packet, then every later packet of any connection restores its mark. The
    # save must precede the restore, otherwise restoring a still-empty conntrack
    # mark would wipe the SO_MARK and send the proxy socket into the tunnel.
    iptables -t mangle -A "$CHAIN_OUT" -m conntrack --ctstate NEW \
        -j CONNMARK --save-mark --nfmask "$FWMARK_HEX" --ctmask "$FWMARK_HEX"
    iptables -t mangle -A "$CHAIN_OUT" \
        -j CONNMARK --restore-mark --nfmask "$FWMARK_HEX" --ctmask "$FWMARK_HEX"

    iptables -t mangle -C PREROUTING -j "$CHAIN_PRE" 2>/dev/null \
        || iptables -t mangle -A PREROUTING -j "$CHAIN_PRE"
    iptables -t mangle -C OUTPUT -j "$CHAIN_OUT" 2>/dev/null \
        || iptables -t mangle -A OUTPUT -j "$CHAIN_OUT"
}

# With IPv4 tunnelled but IPv6 untouched, any dual-stack site would be reached
# over native IPv6 and expose the real address. Block new IPv6 egress while
# leaving established sessions (an IPv6 SSH login) and link-local/ULA alone.
setup_ipv6_block() {
    if [[ "$BLOCK_V6" != "1" ]]; then
        return 0
    fi
    if ! have ip6tables; then
        warn "ip6tables is unavailable; IPv6 leaks are NOT blocked"
        return 0
    fi
    if ! ip6tables -L -n >/dev/null 2>&1; then
        warn "the IPv6 firewall is unusable; skipping leak protection"
        return 0
    fi

    ip6tables -N "$CHAIN_V6" 2>/dev/null || ip6tables -F "$CHAIN_V6"
    ip6tables -A "$CHAIN_V6" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
    ip6tables -A "$CHAIN_V6" -o lo -j RETURN
    ip6tables -A "$CHAIN_V6" -d fe80::/10 -j RETURN
    ip6tables -A "$CHAIN_V6" -d fc00::/7  -j RETURN
    ip6tables -A "$CHAIN_V6" -d ff00::/8  -j RETURN
    ip6tables -A "$CHAIN_V6" -j REJECT --reject-with adm-prohibited
    ip6tables -C OUTPUT -j "$CHAIN_V6" 2>/dev/null || ip6tables -I OUTPUT 1 -j "$CHAIN_V6"
    mkdir -p "$STATE_DIR"
    printf '1\n' >"${STATE_DIR}/v6blocked"
}

teardown_ipv6_block() {
    if ! have ip6tables; then
        return 0
    fi
    while ip6tables -D OUTPUT -j "$CHAIN_V6" 2>/dev/null; do :; done
    ip6tables -F "$CHAIN_V6" 2>/dev/null || true
    ip6tables -X "$CHAIN_V6" 2>/dev/null || true
    rm -f "${STATE_DIR}/v6blocked"
    return 0
}

# --------------------------------------------------------------------------
# DNS
# --------------------------------------------------------------------------

resolved_active() {
    have resolvectl && systemctl is-active --quiet systemd-resolved 2>/dev/null
}

setup_dns() {
    local tmp server

    case "$DNS_MODE" in
        keep) info "DNS left untouched (SOCKHOP_DNS=keep)"; return 0 ;;
        tunnel|tcp) : ;;
        *) die "invalid SOCKHOP_DNS='${DNS_MODE}' (expected tunnel, tcp or keep)" ;;
    esac

    mkdir -p "$STATE_DIR"
    if resolved_active; then
        # Route every domain through the TUN link's resolvers; systemd-resolved
        # then emits its upstream queries from this host, which the tunnel picks
        # up like any other traffic.
        # shellcheck disable=SC2086
        resolvectl dns "$TUN_NAME" $DNS_SERVERS 2>/dev/null || warn "resolvectl dns failed"
        resolvectl domain "$TUN_NAME" "~." 2>/dev/null || warn "resolvectl domain failed"
        printf 'resolved\n' >"${STATE_DIR}/dns.method"
        ok "DNS via systemd-resolved on ${TUN_NAME}: ${DNS_SERVERS}"
        return 0
    fi

    if [[ ! -e "$RESOLV_BACKUP" ]]; then
        if [[ -L /etc/resolv.conf ]]; then
            readlink /etc/resolv.conf >"${STATE_DIR}/resolv.symlink"
        fi
        cp -a /etc/resolv.conf "$RESOLV_BACKUP" 2>/dev/null || : >"$RESOLV_BACKUP"
    fi
    printf 'file\n' >"${STATE_DIR}/dns.method"

    tmp="$(mktemp)"
    {
        printf '# Managed by %s. Original saved at %s\n' "$APP" "$RESOLV_BACKUP"
        for server in $DNS_SERVERS; do
            printf 'nameserver %s\n' "$server"
        done
        printf 'options timeout:2 attempts:2\n'
        # glibc honours use-vc to force TCP, which survives the many SOCKS5
        # servers that refuse UDP ASSOCIATE.
        if [[ "$DNS_MODE" == "tcp" ]]; then
            printf 'options use-vc\n'
        fi
    } >"$tmp"
    rm -f /etc/resolv.conf
    cat "$tmp" >/etc/resolv.conf
    chmod 644 /etc/resolv.conf
    rm -f "$tmp"
    ok "DNS set to: ${DNS_SERVERS} (mode: ${DNS_MODE})"
}

restore_dns() {
    local method=""
    if [[ -r "${STATE_DIR}/dns.method" ]]; then
        method="$(cat "${STATE_DIR}/dns.method")"
    fi

    case "$method" in
        resolved)
            resolvectl revert "$TUN_NAME" 2>/dev/null || true
            ;;
        file)
            if [[ -r "${STATE_DIR}/resolv.symlink" ]]; then
                rm -f /etc/resolv.conf
                ln -sf "$(cat "${STATE_DIR}/resolv.symlink")" /etc/resolv.conf
            elif [[ -e "$RESOLV_BACKUP" ]]; then
                rm -f /etc/resolv.conf
                cp -a "$RESOLV_BACKUP" /etc/resolv.conf
            fi
            rm -f "$RESOLV_BACKUP" "${STATE_DIR}/resolv.symlink"
            ;;
    esac
    rm -f "${STATE_DIR}/dns.method"
    return 0
}

# --------------------------------------------------------------------------
# Process control
# --------------------------------------------------------------------------

t2s_pid() {
    local pid
    if [[ ! -r "$PID_FILE" ]]; then
        return 1
    fi
    pid="$(cat "$PID_FILE" 2>/dev/null || true)"
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
        printf '%s' "$pid"
        return 0
    fi
    return 1
}

start_t2s() {
    local pid size i

    mkdir -p "$RUN_DIR" "$STATE_DIR"
    # Keep the log from growing without bound across restarts.
    if [[ -f "$LOG_FILE" ]]; then
        size="$(stat -c %s "$LOG_FILE" 2>/dev/null || echo 0)"
        if [[ "$size" -gt 10485760 ]]; then
            : >"$LOG_FILE"
        fi
    fi
    touch "$LOG_FILE"; chmod 600 "$LOG_FILE"

    setsid "$T2S_BIN" \
        --device "tun://${TUN_NAME}" \
        --proxy "$P_URL" \
        --fwmark "$FWMARK_DEC" \
        --mtu "$TUN_MTU" \
        --loglevel "$LOGLEVEL" \
        >>"$LOG_FILE" 2>&1 &
    pid=$!
    printf '%s\n' "$pid" >"$PID_FILE"

    for (( i = 0; i < 100; i++ )); do
        if ! kill -0 "$pid" 2>/dev/null; then
            warn "--- last lines of $LOG_FILE ---"
            tail -n 15 "$LOG_FILE" >&2 || true
            die "tun2socks exited during startup"
        fi
        if ip link show "$TUN_NAME" >/dev/null 2>&1; then
            ok "tun2socks running (pid ${pid})"
            return 0
        fi
        sleep 0.1
    done
    die "timed out waiting for device ${TUN_NAME}"
}

stop_t2s() {
    local pid i
    if pid="$(t2s_pid)"; then
        kill "$pid" 2>/dev/null || true
        for (( i = 0; i < 50; i++ )); do
            if ! kill -0 "$pid" 2>/dev/null; then
                break
            fi
            sleep 0.1
        done
        if kill -0 "$pid" 2>/dev/null; then
            kill -9 "$pid" 2>/dev/null || true
        fi
    fi
    rm -f "$PID_FILE"
    ip link del "$TUN_NAME" 2>/dev/null || true
    return 0
}

# --------------------------------------------------------------------------
# Teardown
# --------------------------------------------------------------------------

teardown_net() {
    while ip rule del pref "$PREF_TUN"    2>/dev/null; do :; done
    while ip rule del pref "$PREF_BYPASS" 2>/dev/null; do :; done
    ip route flush table "$RT_TABLE" 2>/dev/null || true

    while iptables -t mangle -D OUTPUT     -j "$CHAIN_OUT" 2>/dev/null; do :; done
    while iptables -t mangle -D PREROUTING -j "$CHAIN_PRE" 2>/dev/null; do :; done
    iptables -t mangle -F "$CHAIN_OUT" 2>/dev/null || true
    iptables -t mangle -X "$CHAIN_OUT" 2>/dev/null || true
    iptables -t mangle -F "$CHAIN_PRE" 2>/dev/null || true
    iptables -t mangle -X "$CHAIN_PRE" 2>/dev/null || true

    teardown_ipv6_block
    restore_rp_filter
    ip route flush cache 2>/dev/null || true
    return 0
}

# A bash ERR trap is not inherited by functions without `set -E`, and `die`
# leaves through exit anyway - so roll back from a single EXIT handler guarded
# by a commit flag. This also covers Ctrl-C midway through setup.
on_exit() {
    local rc=$?
    if [[ "$rc" -ne 0 && "$STARTED" == "1" ]]; then
        STARTED=0
        warn "startup failed - rolling back"
        teardown_net || true
        stop_t2s || true
        restore_dns || true
    fi
    exit "$rc"
}

# --------------------------------------------------------------------------
# Probes
# --------------------------------------------------------------------------

# Talks to 1.1.1.1 by address, so it reports the egress IP even when DNS is
# broken - which is exactly how we tell the two failure modes apart.
probe_ip() {
    curl -4 -s --max-time "${1:-12}" https://1.1.1.1/cdn-cgi/trace 2>/dev/null \
        | sed -n 's/^ip=//p' | head -n1 || true
    return 0
}

# Same endpoint by name: succeeds only if resolution works too.
probe_dns() {
    curl -4 -s --max-time "${1:-12}" https://one.one.one.one/cdn-cgi/trace 2>/dev/null \
        | sed -n 's/^ip=//p' | head -n1 || true
    return 0
}

# Reach the proxy with curl before touching a single route. A wrong password or
# an unreachable endpoint is then a plain error message instead of a rollback.
preflight_proxy() {
    curl -4 -s --max-time 20 --proxy "$P_URL" https://1.1.1.1/cdn-cgi/trace 2>/dev/null \
        | sed -n 's/^ip=//p' | head -n1 || true
    return 0
}

self_test() {
    local egress dns_ip
    info "probing egress"
    egress="$(probe_ip 15)"
    if [[ -z "$egress" ]]; then
        return 1
    fi
    ok "egress IPv4: ${egress}"

    dns_ip="$(probe_dns 15)"
    if [[ -z "$dns_ip" ]]; then
        warn "DNS resolution through the tunnel failed."
        warn "Most SOCKS5 endpoints refuse UDP ASSOCIATE. Retry with: SOCKHOP_DNS=tcp $APP restart"
    else
        ok "DNS through the tunnel works"
    fi
    return 0
}

# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------

cmd_start() {
    local link="${1:-}" original proxy_ip

    require_root
    if [[ -n "$link" ]]; then
        parse_link "$link"
    else
        load_config || die "no link given and no saved config at $CONF_FILE"
    fi

    if t2s_pid >/dev/null; then
        die "already running (pid $(t2s_pid)); use '$APP restart' instead"
    fi

    ensure_deps
    ensure_binary
    detect_uplink
    info "uplink: ${WAN_IF}${WAN_GW:+ via $WAN_GW}"
    info "proxy:  $(redact_url)"

    original="$(probe_ip 8)"
    if [[ -n "$original" ]]; then
        info "current egress: ${original}"
    fi

    info "checking the proxy before changing any routes"
    proxy_ip="$(preflight_proxy)"
    if [[ -z "$proxy_ip" ]]; then
        die "the proxy did not answer - check the address, port and credentials (nothing was changed)"
    fi
    ok "proxy reachable, its egress is ${proxy_ip}"

    save_config
    mkdir -p "$STATE_DIR"
    printf '%s\n' "$WAN_IF" >"${STATE_DIR}/wan_if"

    # From here on any failure must not strand the host without a route.
    trap on_exit EXIT INT TERM
    STARTED=1

    start_t2s
    setup_routing
    setup_iptables
    setup_ipv6_block
    setup_dns

    if ! self_test; then
        warn "no traffic reached the internet through the tunnel - rolling back"
        teardown_net || true
        stop_t2s || true
        restore_dns || true
        STARTED=0
        trap - EXIT INT TERM
        die "check $LOG_FILE for what tun2socks reported"
    fi

    STARTED=0
    trap - EXIT INT TERM
    if [[ -n "$original" ]]; then
        info "was: ${original}  ->  now: $(probe_ip 8)"
    fi
    ok "tunnel is up. Run '$APP stop' to restore the original egress."
}

cmd_stop() {
    local now
    require_root
    info "tearing down"
    teardown_net
    stop_t2s
    restore_dns
    ok "original egress restored"
    now="$(probe_ip 8)"
    if [[ -n "$now" ]]; then
        info "egress IPv4: ${now}"
    fi
    return 0
}

cmd_status() {
    local pid state egress

    if pid="$(t2s_pid)"; then
        state="${C_GRN}running${C_RST} (pid ${pid})"
    else
        state="${C_RED}stopped${C_RST}"
        if [[ -e "$PID_FILE" ]]; then
            state="${state} ${C_YEL}(stale pidfile - routes may still be in place)${C_RST}"
        fi
    fi
    printf '%s=== sockhop status ===%s\n' "$C_CYA" "$C_RST"
    printf 'tun2socks : %s\n' "$state"

    if load_config 2>/dev/null; then
        printf 'proxy     : %s\n' "$(redact_url)"
    else
        printf 'proxy     : %s(not configured)%s\n' "$C_DIM" "$C_RST"
    fi

    if ip link show "$TUN_NAME" >/dev/null 2>&1; then
        printf 'device    : %s (%s)\n' "$TUN_NAME" \
            "$(ip -o link show "$TUN_NAME" | awk '{print $9}')"
    else
        printf 'device    : %s(absent)%s\n' "$C_DIM" "$C_RST"
    fi

    printf 'dns mode  : %s\n' "$DNS_MODE"
    if [[ -e "${STATE_DIR}/v6blocked" ]]; then
        printf 'ipv6      : egress blocked\n'
    else
        printf 'ipv6      : untouched\n'
    fi

    printf '\n%srules%s\n' "$C_DIM" "$C_RST"
    ip rule show | grep -E "^(${PREF_BYPASS}|${PREF_TUN}):" \
        || printf '  %s(none)%s\n' "$C_DIM" "$C_RST"
    printf '\n%stable %s%s\n' "$C_DIM" "$RT_TABLE" "$C_RST"
    ip route show table "$RT_TABLE" 2>/dev/null | head -n 4 \
        || printf '  %s(empty)%s\n' "$C_DIM" "$C_RST"

    printf '\n'
    egress="$(probe_ip 10)"
    if [[ -n "$egress" ]]; then
        printf 'egress IPv4: %s%s%s\n' "$C_GRN" "$egress" "$C_RST"
    else
        printf 'egress IPv4: %sunreachable%s\n' "$C_RED" "$C_RST"
    fi
    return 0
}

cmd_test() {
    local egress dns_ip
    egress="$(probe_ip 15)"
    if [[ -z "$egress" ]]; then
        die "no IPv4 connectivity"
    fi
    ok "egress IPv4 : ${egress}"

    dns_ip="$(probe_dns 15)"
    if [[ -n "$dns_ip" ]]; then
        ok "DNS         : working"
    else
        warn "DNS         : failing (try SOCKHOP_DNS=tcp $APP restart)"
    fi
    return 0
}

cmd_install() {
    local link="${1:-}" src

    require_root
    if [[ -n "$link" ]]; then
        parse_link "$link"
        save_config
    fi

    src="$(readlink -f "$0")"
    if [[ "$src" != "$SELF_BIN" ]]; then
        install -m 0755 "$src" "$SELF_BIN"
    fi

    cat >"$SERVICE_FILE" <<EOF
[Unit]
Description=sockhop - SOCKS5 IPv4 egress tunnel
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=${SELF_BIN} start
ExecStop=${SELF_BIN} stop
TimeoutStartSec=120

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable "${APP}.service" >/dev/null 2>&1 || warn "systemctl enable failed"
    ok "installed. Control it with: systemctl start|stop|status ${APP}"
}

cmd_uninstall() {
    require_root
    systemctl disable --now "${APP}.service" >/dev/null 2>&1 || true
    cmd_stop || true
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload 2>/dev/null || true
    rm -rf "$CONF_DIR" "$STATE_DIR" "$RUN_DIR"
    ok "removed the service and saved state (binaries in /usr/local/bin were kept)"
}

cmd_logs() {
    if [[ ! -r "$LOG_FILE" ]]; then
        die "no log at $LOG_FILE"
    fi
    if [[ "${1:-}" == "-f" ]]; then
        tail -f "$LOG_FILE"
    else
        tail -n 50 "$LOG_FILE"
    fi
}

usage() {
    cat <<EOF
${APP} - send all IPv4 egress through a SOCKS5 proxy (Debian/Ubuntu)

Usage:
  ${APP} start [LINK]     bring the tunnel up (LINK is saved for later runs)
  ${APP} stop             tear down and restore the original egress
  ${APP} restart [LINK]
  ${APP} status           show state, rules and the current egress IP
  ${APP} test             probe egress IP and DNS
  ${APP} install [LINK]   copy to ${SELF_BIN} and enable the systemd unit
  ${APP} uninstall        remove the unit, config and state
  ${APP} logs [-f]        show the tun2socks log

Accepted LINK formats:
  socks5://user:pass@host:port        socks5h://user:pass@host:port
  socks://<base64(user:pass)>@host:port
  socks://<base64(user:pass@host:port)>
  user:pass@host:port                 host:port:user:pass         host:port

Environment overrides:
  SOCKHOP_DNS=tunnel|tcp|keep   DNS strategy                  (default: tunnel)
                                tcp adds glibc's 'options use-vc' so lookups
                                go over TCP, for proxies that refuse UDP
  SOCKHOP_DNS_SERVERS="1.1.1.1 8.8.8.8"
  SOCKHOP_BLOCK_V6=1|0          block IPv6 egress leaks       (default: 1)
  SOCKHOP_BYPASS="203.0.113.0/24 ..."   extra CIDRs kept off the tunnel
  SOCKHOP_BINARY=/path/to/tun2socks     use a local binary instead of downloading
  SOCKHOP_MIRROR=https://ghproxy.example   download prefix for GitHub
  SOCKHOP_T2S_VERSION=${T2S_VERSION}
  SOCKHOP_TUN_NAME=${TUN_NAME}   SOCKHOP_MTU=${TUN_MTU}
  SOCKHOP_FWMARK=${FWMARK_DEC}   SOCKHOP_TABLE=${RT_TABLE}
EOF
}

main() {
    local cmd="${1:-}"
    if [[ $# -gt 0 ]]; then
        shift
    fi
    case "$cmd" in
        start)     cmd_start "${1:-}" ;;
        stop)      cmd_stop ;;
        restart)   cmd_stop || true; cmd_start "${1:-}" ;;
        status)    cmd_status ;;
        test)      cmd_test ;;
        install)   cmd_install "${1:-}" ;;
        uninstall) cmd_uninstall ;;
        logs)      cmd_logs "${1:-}" ;;
        ""|-h|--help|help) usage ;;
        *) die "unknown command '${cmd}'; run '${APP} --help'" ;;
    esac
}

main "$@"
