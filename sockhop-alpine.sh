#!/bin/sh
#
# sockhop - route all IPv4 egress traffic of this host through a SOCKS5 proxy.
# Target: Alpine Linux (OpenRC, musl, busybox ash). POSIX sh only - no bashisms.
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
# In an LXC/Docker container add: --cap-add NET_ADMIN --device /dev/net/tun

set -eu

APP="sockhop"
CONF_DIR="/etc/sockhop"
CONF_FILE="${CONF_DIR}/config"
STATE_DIR="/var/lib/sockhop"
RUN_DIR="/run/sockhop"
PID_FILE="${RUN_DIR}/tun2socks.pid"
LOG_FILE="/var/log/sockhop.log"
T2S_BIN="/usr/local/bin/tun2socks"
SELF_BIN="/usr/local/bin/sockhop"
INIT_FILE="/etc/init.d/sockhop"
RESOLV_BACKUP="${STATE_DIR}/resolv.conf.bak"
UNBOUND_CONF="/etc/unbound/sockhop.conf"
UNBOUND_PID="${RUN_DIR}/unbound.pid"

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

if [ -t 1 ]; then
    C_RED=$(printf '\033[31m'); C_GRN=$(printf '\033[32m')
    C_YEL=$(printf '\033[33m'); C_CYA=$(printf '\033[36m')
    C_DIM=$(printf '\033[2m');  C_RST=$(printf '\033[0m')
else
    C_RED=""; C_GRN=""; C_YEL=""; C_CYA=""; C_DIM=""; C_RST=""
fi

info() { printf '%s[*]%s %s\n' "$C_CYA" "$C_RST" "$*"; }
ok()   { printf '%s[+]%s %s\n' "$C_GRN" "$C_RST" "$*"; }
warn() { printf '%s[!]%s %s\n' "$C_YEL" "$C_RST" "$*" >&2; }
die()  { printf '%s[x]%s %s\n' "$C_RED" "$C_RST" "$*" >&2; exit 1; }

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        die "must run as root"
    fi
}

have() { command -v "$1" >/dev/null 2>&1; }

# busybox sleep understands fractions, but fall back if this build does not.
nap() { sleep 0.1 2>/dev/null || sleep 1; }

is_ipv4() {
    case "$1" in
        *[!0-9.]*) return 1 ;;
        *.*.*.*)   return 0 ;;
        *)         return 1 ;;
    esac
}

is_port() {
    case "$1" in
        ''|*[!0-9]*) return 1 ;;
    esac
    [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

# --------------------------------------------------------------------------
# Node link parsing
# --------------------------------------------------------------------------

# Only %HH sequences are turned into escapes, so a stray '%' in a hand-written
# password cannot corrupt the rest of the string. \xHH is understood by both
# bash and busybox printf.
urldecode() {
    _u=$(printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/%\([0-9a-fA-F][0-9a-fA-F]\)/\\x\1/g')
    printf '%b' "$_u"
}

# Escape only what actually breaks a URL userinfo field. '%' must go first.
urlencode() {
    printf '%s' "$1" | sed -e 's/%/%25/g' -e 's/:/%3A/g' -e 's/@/%40/g' \
        -e 's|/|%2F|g' -e 's/?/%3F/g' -e 's/#/%23/g' \
        -e 's/\[/%5B/g' -e 's/\]/%5D/g' -e 's/ /%20/g'
}

b64d() {
    _s=$(printf '%s' "$1" | tr -- '-_' '+/')
    case $(( ${#_s} % 4 )) in
        2) _s="${_s}==" ;;
        3) _s="${_s}=" ;;
        1) return 1 ;;
    esac
    printf '%s' "$_s" | base64 -d 2>/dev/null
}

split_hostport() {
    _hp="$1"
    case "$_hp" in
        \[*\]:*)
            P_HOST=$(printf '%s' "$_hp" | sed 's/^\[\(.*\)\]:.*$/\1/')
            P_PORT=$(printf '%s' "$_hp" | sed 's/^.*\]://')
            ;;
        *:*)
            P_HOST="${_hp%:*}"
            P_PORT="${_hp##*:}"
            ;;
        *)
            die "link is missing a port: $_hp"
            ;;
    esac
    if [ -z "$P_HOST" ]; then
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
    _raw="$1"
    _depth="${2:-0}"
    if [ "$_depth" -ge 3 ]; then
        die "link is nested too deeply"
    fi

    _raw=$(printf '%s' "$_raw" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's/#.*$//')
    if [ -z "$_raw" ]; then
        die "empty link"
    fi

    case "$_raw" in
        *://*)
            _scheme=$(printf '%s' "${_raw%%://*}" | tr '[:upper:]' '[:lower:]')
            _body="${_raw#*://}"
            case "$_scheme" in
                socks5|socks5h|socks|socks5t) : ;;
                *) die "unsupported scheme '${_scheme}': only socks5/socks5h/socks are accepted" ;;
            esac
            ;;
        *)
            _body="$_raw"
            ;;
    esac
    _body="${_body%/}"
    if [ -z "$_body" ]; then
        die "link has no body"
    fi

    case "$_body" in
        *@*) : ;;
        *)
            # host:port:user:pass - the flat form most proxy vendors hand out.
            _fields=$(printf '%s' "$_body" | awk -F: '{print NF}')
            if [ "$_fields" -eq 4 ]; then
                P_HOST=$(printf '%s' "$_body" | cut -d: -f1)
                P_PORT=$(printf '%s' "$_body" | cut -d: -f2)
                P_USER=$(printf '%s' "$_body" | cut -d: -f3)
                P_PASS=$(printf '%s' "$_body" | cut -d: -f4)
                if ! is_port "$P_PORT"; then
                    die "invalid port in link: $P_PORT"
                fi
                build_url
                return 0
            fi
            # Whole payload base64-encoded (socks://<base64 of user:pass@host:port>).
            case "$_body" in
                *:*) : ;;
                *)
                    _decoded=$(b64d "$_body") || die "link is neither host:port nor valid base64"
                    if [ -z "$_decoded" ]; then
                        die "base64 payload decoded to nothing"
                    fi
                    parse_link "socks5://${_decoded}" $((_depth + 1))
                    return 0
                    ;;
            esac
            ;;
    esac

    case "$_body" in
        *@*)
            _userinfo="${_body%@*}"          # last @ splits creds from host
            _hostport="${_body##*@}"
            case "$_userinfo" in
                *:*)
                    P_USER=$(urldecode "${_userinfo%%:*}")
                    P_PASS=$(urldecode "${_userinfo#*:}")
                    ;;
                *)
                    # v2rayN-style socks://<base64(user:pass)>@host:port
                    _decoded=$(b64d "$_userinfo") || die "cannot decode credentials in link"
                    case "$_decoded" in
                        *:*) : ;;
                        *) die "decoded credentials are not user:pass" ;;
                    esac
                    P_USER="${_decoded%%:*}"
                    P_PASS="${_decoded#*:}"
                    ;;
            esac
            ;;
        *)
            _hostport="$_body"
            ;;
    esac

    split_hostport "$_hostport"
    build_url
}

build_url() {
    if [ -n "$P_USER" ]; then
        P_URL="socks5://$(urlencode "$P_USER"):$(urlencode "$P_PASS")@${P_HOST}:${P_PORT}"
    else
        P_URL="socks5://${P_HOST}:${P_PORT}"
    fi
}

redact_url() {
    if [ -n "$P_USER" ]; then
        printf 'socks5://%s:****@%s:%s' "$P_USER" "$P_HOST" "$P_PORT"
    else
        printf 'socks5://%s:%s' "$P_HOST" "$P_PORT"
    fi
}

save_config() {
    mkdir -p "$CONF_DIR"
    _enc=$(printf '%s' "$P_URL" | base64 | tr -d '\n')
    umask 077
    {
        printf '# Managed by %s. Contains proxy credentials - keep mode 0600.\n' "$APP"
        printf 'SOCKHOP_LINK_B64=%s\n' "$_enc"
        printf 'SOCKHOP_HOST=%s\n' "$P_HOST"
        printf 'SOCKHOP_PORT=%s\n' "$P_PORT"
    } >"$CONF_FILE"
    chmod 600 "$CONF_FILE"
}

load_config() {
    if [ ! -r "$CONF_FILE" ]; then
        return 1
    fi
    _b64=$(sed -n 's/^SOCKHOP_LINK_B64=//p' "$CONF_FILE" | head -n1)
    if [ -z "$_b64" ]; then
        return 1
    fi
    parse_link "$(printf '%s' "$_b64" | base64 -d)"
}

# --------------------------------------------------------------------------
# Environment discovery
# --------------------------------------------------------------------------

# Resolve the uplink through the bypass mark, so this reports the physical
# link even when the tunnel is already up and owns the unmarked default route.
detect_uplink() {
    _line=$(ip -4 route get 1.1.1.1 mark "$FWMARK_HEX" 2>/dev/null | head -n1 || true)
    if [ -z "$_line" ]; then
        _line=$(ip -4 route show default 2>/dev/null | head -n1 || true)
    fi
    if [ -z "$_line" ]; then
        die "no IPv4 default route; cannot determine the uplink"
    fi

    WAN_IF=$(printf '%s' "$_line" | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
    WAN_GW=$(printf '%s' "$_line" | awk '{for(i=1;i<=NF;i++) if($i=="via"){print $(i+1); exit}}')
    if [ -z "$WAN_IF" ]; then
        die "could not parse the uplink interface from: $_line"
    fi
    if [ "$WAN_IF" = "$TUN_NAME" ]; then
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
    _missing=""
    have ip       || _missing="$_missing iproute2"
    have iptables || _missing="$_missing iptables"
    have curl     || _missing="$_missing curl"
    have unzip    || _missing="$_missing unzip"

    if [ -n "$_missing" ]; then
        info "installing:$_missing"
        # shellcheck disable=SC2086
        apk add --no-cache ca-certificates $_missing >/dev/null 2>&1 \
            || die "apk add failed for:$_missing"
    fi

    # busybox ships a cut-down `ip` without policy routing; insist on iproute2.
    ip rule show >/dev/null 2>&1 || die \
        "'ip rule' is unavailable - install the full iproute2 package (apk add iproute2)"

    if [ ! -c /dev/net/tun ]; then
        modprobe tun 2>/dev/null || true
        if [ ! -c /dev/net/tun ]; then
            mkdir -p /dev/net 2>/dev/null || true
            mknod /dev/net/tun c 10 200 2>/dev/null || true
            chmod 600 /dev/net/tun 2>/dev/null || true
        fi
        if [ ! -c /dev/net/tun ]; then
            die "/dev/net/tun is missing. On a container, pass --device /dev/net/tun --cap-add NET_ADMIN."
        fi
    fi

    iptables -t mangle -L >/dev/null 2>&1 || die \
        "iptables cannot reach the mangle table - missing kernel modules or NET_ADMIN"
}

ensure_binary() {
    if [ -n "${SOCKHOP_BINARY:-}" ]; then
        if [ ! -x "$SOCKHOP_BINARY" ]; then
            die "SOCKHOP_BINARY is not executable: $SOCKHOP_BINARY"
        fi
        install -m 0755 "$SOCKHOP_BINARY" "$T2S_BIN"
        return 0
    fi
    if [ -x "$T2S_BIN" ]; then
        return 0
    fi

    _arch=$(detect_arch)
    _url="${T2S_MIRROR}/xjasonlyu/tun2socks/releases/download/${T2S_VERSION}/tun2socks-linux-${_arch}.zip"
    _tmp=$(mktemp -d)

    info "downloading tun2socks ${T2S_VERSION} (${_arch})"
    if ! curl -fsSL --retry 3 --connect-timeout 15 -o "${_tmp}/t2s.zip" "$_url"; then
        rm -rf "$_tmp"
        die "download failed: $_url (set SOCKHOP_MIRROR or SOCKHOP_BINARY)"
    fi
    if ! unzip -oq "${_tmp}/t2s.zip" -d "$_tmp"; then
        rm -rf "$_tmp"
        die "failed to unpack the archive"
    fi

    _extracted=$(find "$_tmp" -type f -name 'tun2socks*' ! -name '*.zip' | head -n1)
    if [ -z "$_extracted" ]; then
        rm -rf "$_tmp"
        die "no tun2socks binary inside the archive"
    fi
    install -m 0755 "$_extracted" "$T2S_BIN"
    rm -rf "$_tmp"

    # The releases are static Go builds, so they run on musl - but verify
    # rather than assume.
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
    _all="/proc/sys/net/ipv4/conf/all/rp_filter"
    _dev="/proc/sys/net/ipv4/conf/${TUN_NAME}/rp_filter"

    mkdir -p "$STATE_DIR"
    if [ -r "$_all" ]; then
        _now=$(cat "$_all" 2>/dev/null || echo 0)
        printf '%s\n' "$_now" >"${STATE_DIR}/rp_filter.all"
        if [ "$_now" = "1" ]; then
            printf '2\n' >"$_all" 2>/dev/null || true
        fi
    fi
    if [ -w "$_dev" ]; then
        printf '0\n' >"$_dev" 2>/dev/null || true
    fi
    return 0
}

restore_rp_filter() {
    _file="${STATE_DIR}/rp_filter.all"
    _all="/proc/sys/net/ipv4/conf/all/rp_filter"
    if [ -r "$_file" ] && [ -w "$_all" ]; then
        _saved=$(cat "$_file")
        if [ -n "$_saved" ]; then
            printf '%s\n' "$_saved" >"$_all" 2>/dev/null || true
        fi
    fi
    rm -f "$_file"
    return 0
}

# musl systems often lack getent, so fall back to busybox nslookup.
resolve_host() {
    if have getent; then
        getent ahostsv4 "$1" 2>/dev/null | awk '{print $1}' | sort -u || true
    elif have nslookup; then
        nslookup "$1" 2>/dev/null \
            | awk '/^Address/ {print $NF}' \
            | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | sort -u || true
    fi
    return 0
}

setup_routing() {
    ip addr replace "${TUN_ADDR}/${TUN_PREFIX}" dev "$TUN_NAME"
    ip link set dev "$TUN_NAME" up
    ip link set dev "$TUN_NAME" mtu "$TUN_MTU" 2>/dev/null || true
    tune_rp_filter

    ip route flush table "$RT_TABLE" 2>/dev/null || true
    ip route add default dev "$TUN_NAME" table "$RT_TABLE"

    # `throw` ends the lookup in this table and lets the kernel fall through to
    # the next rule (main), so bypassed destinations keep their normal path
    # even if the gateway changes later.
    for _cidr in $BYPASS_V4 $BYPASS_EXTRA; do
        ip route add throw "$_cidr" table "$RT_TABLE" 2>/dev/null || true
    done
    # Belt and braces alongside the fwmark rule: keep the proxy itself direct.
    if is_ipv4 "$P_HOST"; then
        ip route add throw "${P_HOST}/32" table "$RT_TABLE" 2>/dev/null || true
    else
        for _a in $(resolve_host "$P_HOST"); do
            ip route add throw "${_a}/32" table "$RT_TABLE" 2>/dev/null || true
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
    if [ "$BLOCK_V6" != "1" ]; then
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
#
# musl has no equivalent of glibc's `options use-vc`, so DNS_MODE=tcp cannot be
# expressed in resolv.conf here. Instead a private unbound instance forwards
# over TCP, which is what makes the tunnel usable with the many SOCKS5
# endpoints that refuse UDP ASSOCIATE.
# --------------------------------------------------------------------------

port53_free() {
    if have ss; then
        ! ss -lnu 2>/dev/null | grep -q ':53[[:space:]]'
    elif have netstat; then
        ! netstat -lnu 2>/dev/null | grep -q ':53[[:space:]]'
    else
        return 0
    fi
}

start_unbound() {
    if ! have unbound; then
        if ! apk add --no-cache unbound >/dev/null 2>&1; then
            warn "unbound could not be installed; falling back to DNS over the tunnel (UDP)"
            return 1
        fi
    fi
    if ! port53_free; then
        warn "127.0.0.1:53 is already in use; skipping the TCP resolver"
        return 1
    fi

    mkdir -p /etc/unbound "$RUN_DIR"
    {
        printf 'server:\n'
        printf '    verbosity: 0\n'
        printf '    interface: 127.0.0.1\n'
        printf '    port: 53\n'
        printf '    do-ip6: no\n'
        printf '    access-control: 127.0.0.0/8 allow\n'
        printf '    access-control: 0.0.0.0/0 refuse\n'
        # The iterator alone avoids needing a DNSSEC trust anchor at boot, which
        # cannot be fetched before the tunnel is up.
        printf '    module-config: "iterator"\n'
        printf '    tcp-upstream: yes\n'
        printf '    do-daemonize: yes\n'
        printf '    pidfile: "%s"\n' "$UNBOUND_PID"
        printf '    username: ""\n'
        printf '    chroot: ""\n'
        printf '    directory: "/etc/unbound"\n'
        printf '    logfile: ""\n'
        printf 'forward-zone:\n'
        printf '    name: "."\n'
        for _s in $DNS_SERVERS; do
            printf '    forward-addr: %s\n' "$_s"
        done
    } >"$UNBOUND_CONF"

    if ! unbound -c "$UNBOUND_CONF" 2>/dev/null; then
        warn "unbound failed to start; falling back to DNS over the tunnel (UDP)"
        return 1
    fi
    return 0
}

stop_unbound() {
    if [ -r "$UNBOUND_PID" ]; then
        _p=$(cat "$UNBOUND_PID" 2>/dev/null || true)
        if [ -n "$_p" ]; then
            kill "$_p" 2>/dev/null || true
        fi
        rm -f "$UNBOUND_PID"
    fi
    rm -f "$UNBOUND_CONF"
    return 0
}

write_resolv() {
    _tmp=$(mktemp)
    {
        printf '# Managed by %s. Original saved at %s\n' "$APP" "$RESOLV_BACKUP"
        for _s in "$@"; do
            printf 'nameserver %s\n' "$_s"
        done
        printf 'options timeout:2 attempts:2\n'
    } >"$_tmp"
    rm -f /etc/resolv.conf
    cat "$_tmp" >/etc/resolv.conf
    chmod 644 /etc/resolv.conf
    rm -f "$_tmp"
}

backup_resolv() {
    mkdir -p "$STATE_DIR"
    if [ -e "$RESOLV_BACKUP" ]; then
        return 0
    fi
    if [ -L /etc/resolv.conf ]; then
        readlink /etc/resolv.conf >"${STATE_DIR}/resolv.symlink"
    fi
    cp -a /etc/resolv.conf "$RESOLV_BACKUP" 2>/dev/null || : >"$RESOLV_BACKUP"
    return 0
}

setup_dns() {
    case "$DNS_MODE" in
        keep) info "DNS left untouched (SOCKHOP_DNS=keep)"; return 0 ;;
        tunnel|tcp) : ;;
        *) die "invalid SOCKHOP_DNS='${DNS_MODE}' (expected tunnel, tcp or keep)" ;;
    esac

    backup_resolv
    if [ "$DNS_MODE" = "tcp" ] && start_unbound; then
        write_resolv 127.0.0.1
        printf 'unbound\n' >"${STATE_DIR}/dns.method"
        ok "DNS via a local unbound forwarding over TCP to: ${DNS_SERVERS}"
        return 0
    fi

    # shellcheck disable=SC2086
    write_resolv $DNS_SERVERS
    printf 'file\n' >"${STATE_DIR}/dns.method"
    ok "DNS set to: ${DNS_SERVERS} (queried over the tunnel via UDP)"
}

restore_dns() {
    _method=""
    if [ -r "${STATE_DIR}/dns.method" ]; then
        _method=$(cat "${STATE_DIR}/dns.method")
    fi
    if [ -z "$_method" ]; then
        return 0
    fi
    if [ "$_method" = "unbound" ]; then
        stop_unbound
    fi

    if [ -r "${STATE_DIR}/resolv.symlink" ]; then
        rm -f /etc/resolv.conf
        ln -sf "$(cat "${STATE_DIR}/resolv.symlink")" /etc/resolv.conf
    elif [ -e "$RESOLV_BACKUP" ]; then
        rm -f /etc/resolv.conf
        cp -a "$RESOLV_BACKUP" /etc/resolv.conf
    fi
    rm -f "$RESOLV_BACKUP" "${STATE_DIR}/resolv.symlink" "${STATE_DIR}/dns.method"
    return 0
}

# --------------------------------------------------------------------------
# Process control
# --------------------------------------------------------------------------

t2s_pid() {
    if [ ! -r "$PID_FILE" ]; then
        return 1
    fi
    _pid=$(cat "$PID_FILE" 2>/dev/null || true)
    if [ -n "$_pid" ] && kill -0 "$_pid" 2>/dev/null; then
        printf '%s' "$_pid"
        return 0
    fi
    return 1
}

start_t2s() {
    mkdir -p "$RUN_DIR" "$STATE_DIR"
    # Keep the log from growing without bound across restarts.
    if [ -f "$LOG_FILE" ]; then
        _sz=$(stat -c %s "$LOG_FILE" 2>/dev/null || echo 0)
        if [ "$_sz" -gt 10485760 ]; then
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
    _pid=$!
    printf '%s\n' "$_pid" >"$PID_FILE"

    _i=0
    while [ "$_i" -lt 100 ]; do
        if ! kill -0 "$_pid" 2>/dev/null; then
            warn "--- last lines of $LOG_FILE ---"
            tail -n 15 "$LOG_FILE" >&2 || true
            die "tun2socks exited during startup"
        fi
        if ip link show "$TUN_NAME" >/dev/null 2>&1; then
            ok "tun2socks running (pid ${_pid})"
            return 0
        fi
        nap
        _i=$((_i + 1))
    done
    die "timed out waiting for device ${TUN_NAME}"
}

stop_t2s() {
    if _pid=$(t2s_pid); then
        kill "$_pid" 2>/dev/null || true
        _i=0
        while [ "$_i" -lt 50 ]; do
            if ! kill -0 "$_pid" 2>/dev/null; then
                break
            fi
            nap
            _i=$((_i + 1))
        done
        if kill -0 "$_pid" 2>/dev/null; then
            kill -9 "$_pid" 2>/dev/null || true
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

# ash has no ERR trap, and `die` leaves through exit anyway - so roll back from
# a single EXIT handler guarded by a commit flag. This also covers Ctrl-C
# midway through setup.
on_exit() {
    _rc=$?
    if [ "$_rc" -ne 0 ] && [ "$STARTED" = "1" ]; then
        STARTED=0
        warn "startup failed - rolling back"
        teardown_net || true
        stop_t2s || true
        restore_dns || true
    fi
    exit "$_rc"
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
    info "probing egress"
    _egress=$(probe_ip 15)
    if [ -z "$_egress" ]; then
        return 1
    fi
    ok "egress IPv4: ${_egress}"

    _dns=$(probe_dns 15)
    if [ -z "$_dns" ]; then
        warn "DNS resolution through the tunnel failed."
        warn "Most SOCKS5 endpoints refuse UDP ASSOCIATE. Retry with: $APP restart --dns tcp"
    else
        ok "DNS through the tunnel works"
    fi
    return 0
}

# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------

cmd_start() {
    _link="${1:-}"

    require_root
    if [ -n "$_link" ]; then
        parse_link "$_link"
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

    _original=$(probe_ip 8)
    if [ -n "$_original" ]; then
        info "current egress: ${_original}"
    fi

    info "checking the proxy before changing any routes"
    _proxy_ip=$(preflight_proxy)
    if [ -z "$_proxy_ip" ]; then
        die "the proxy did not answer - check the address, port and credentials (nothing was changed)"
    fi
    ok "proxy reachable, its egress is ${_proxy_ip}"

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
    if [ -n "$_original" ]; then
        info "was: ${_original}  ->  now: $(probe_ip 8)"
    fi
    ok "tunnel is up. Run '$APP stop' to restore the original egress."
}

cmd_stop() {
    require_root
    info "tearing down"
    teardown_net
    stop_t2s
    restore_dns
    ok "original egress restored"
    _now=$(probe_ip 8)
    if [ -n "$_now" ]; then
        info "egress IPv4: ${_now}"
    fi
    return 0
}

cmd_status() {
    if _pid=$(t2s_pid); then
        _state="${C_GRN}running${C_RST} (pid ${_pid})"
    else
        _state="${C_RED}stopped${C_RST}"
        if [ -e "$PID_FILE" ]; then
            _state="${_state} ${C_YEL}(stale pidfile - routes may still be in place)${C_RST}"
        fi
    fi
    printf '%s=== sockhop status ===%s\n' "$C_CYA" "$C_RST"
    printf 'tun2socks : %s\n' "$_state"

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
    if [ -e "${STATE_DIR}/v6blocked" ]; then
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
    _egress=$(probe_ip 10)
    if [ -n "$_egress" ]; then
        printf 'egress IPv4: %s%s%s\n' "$C_GRN" "$_egress" "$C_RST"
    else
        printf 'egress IPv4: %sunreachable%s\n' "$C_RED" "$C_RST"
    fi
    return 0
}

cmd_test() {
    _egress=$(probe_ip 15)
    if [ -z "$_egress" ]; then
        die "no IPv4 connectivity"
    fi
    ok "egress IPv4 : ${_egress}"

    _dns=$(probe_dns 15)
    if [ -n "$_dns" ]; then
        ok "DNS         : working"
    else
        warn "DNS         : failing (try: $APP restart --dns tcp)"
    fi
    return 0
}

cmd_install() {
    require_root
    _link="${1:-}"
    if [ -n "$_link" ]; then
        parse_link "$_link"
        save_config
    fi

    _src=$(readlink -f "$0")
    if [ "$_src" != "$SELF_BIN" ]; then
        install -m 0755 "$_src" "$SELF_BIN"
    fi

    cat >"$INIT_FILE" <<EOF
#!/sbin/openrc-run

name="sockhop"
description="SOCKS5 IPv4 egress tunnel"

depend() {
    need net
    after firewall
}

start() {
    ebegin "Starting sockhop"
    ${SELF_BIN} start
    eend \$?
}

stop() {
    ebegin "Stopping sockhop"
    ${SELF_BIN} stop
    eend \$?
}
EOF
    chmod 755 "$INIT_FILE"
    rc-update add "$APP" default >/dev/null 2>&1 || warn "rc-update add failed"
    ok "installed. Control it with: rc-service ${APP} start|stop"
}

cmd_uninstall() {
    require_root
    rc-service "$APP" stop >/dev/null 2>&1 || true
    rc-update del "$APP" default >/dev/null 2>&1 || true
    cmd_stop || true
    rm -f "$INIT_FILE"
    rm -rf "$CONF_DIR" "$STATE_DIR" "$RUN_DIR"
    ok "removed the service and saved state (binaries in /usr/local/bin were kept)"
}

cmd_logs() {
    if [ ! -r "$LOG_FILE" ]; then
        die "no log at $LOG_FILE"
    fi
    if [ "${1:-}" = "-f" ]; then
        tail -f "$LOG_FILE"
    else
        tail -n 50 "$LOG_FILE"
    fi
}

usage() {
    cat <<EOF
${APP} - send all IPv4 egress through a SOCKS5 proxy (Alpine Linux)

Usage:
  ${APP} start [LINK]     bring the tunnel up (LINK is saved for later runs)
  ${APP} stop             tear down and restore the original egress
  ${APP} restart [LINK]
  ${APP} status           show state, rules and the current egress IP
  ${APP} test             probe egress IP and DNS
  ${APP} install [LINK]   copy to ${SELF_BIN} and add the OpenRC service
  ${APP} uninstall        remove the service, config and state
  ${APP} logs [-f]        show the tun2socks log

Options:
  --dns tunnel|tcp|keep   DNS strategy for this run. Prefer this over the
                          environment variable: 'SOCKHOP_DNS=tcp sudo ...'
                          silently loses the value to sudo's env_reset, the
                          variable has to come after sudo.
                            tunnel  lookups travel the tunnel over UDP
                            tcp     private unbound forwarding over TCP, for
                                    the many SOCKS5 nodes that refuse UDP
                            keep    do not touch DNS at all

Accepted LINK formats:
  socks5://user:pass@host:port        socks5h://user:pass@host:port
  socks://<base64(user:pass)>@host:port
  socks://<base64(user:pass@host:port)>
  user:pass@host:port                 host:port:user:pass         host:port

Environment overrides:
  SOCKHOP_DNS=tunnel|tcp|keep   DNS strategy                  (default: tunnel)
                                tcp starts a private unbound forwarding over
                                TCP, since musl has no 'options use-vc'
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
    _cmd=""; _arg=""

    # Options are scanned out of the argument list wherever they appear, so
    # `restart --dns tcp` works. A command-line flag is deliberately offered
    # alongside the environment variables: `SOCKHOP_DNS=x sudo ...` silently
    # loses the variable to sudo's env_reset, which is a trap worth closing.
    while [ $# -gt 0 ]; do
        case "$1" in
            --dns=*)
                DNS_MODE="${1#*=}"
                ;;
            --dns)
                if [ $# -lt 2 ]; then
                    die "--dns needs a value: tunnel, tcp or keep"
                fi
                DNS_MODE="$2"
                shift
                ;;
            *)
                if [ -z "$_cmd" ]; then
                    _cmd="$1"
                elif [ -z "$_arg" ]; then
                    _arg="$1"
                fi
                ;;
        esac
        shift
    done

    case "$DNS_MODE" in
        tunnel|tcp|keep) : ;;
        *) die "invalid DNS mode '${DNS_MODE}' (expected tunnel, tcp or keep)" ;;
    esac

    case "$_cmd" in
        start)     cmd_start "$_arg" ;;
        stop)      cmd_stop ;;
        restart)   cmd_stop || true; cmd_start "$_arg" ;;
        status)    cmd_status ;;
        test)      cmd_test ;;
        install)   cmd_install "$_arg" ;;
        uninstall) cmd_uninstall ;;
        logs)      cmd_logs "$_arg" ;;
        ""|-h|--help|help) usage ;;
        *) die "unknown command '${_cmd}'; run '${APP} --help'" ;;
    esac
}

main "$@"
