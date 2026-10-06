#!/usr/bin/env bash
# =============================================================================
#   FASTDNS MODED INSTALLER  -  DNSTT + EDNS proxy (C) + MTU 1800 + tuning
# =============================================================================
#   Supports : Ubuntu 20.04 - 26.04, Debian 10 - 13 (and apt-based derivatives
#              such as Mint, Kali, Raspberry Pi OS)
#   Repo     : https://github.com/wavy07/script4  ->  "DNSTT MODED" folder
#   Files    : dnstt-server, server.key, server.pub, moded.sh
#
#   Run:
#     bash <(curl -fsSL "https://raw.githubusercontent.com/wavy07/script4/main/DNSTT%20MODED/moded.sh")
#   or non-interactive:
#     NS_DOMAIN=t.example.com bash moded.sh
#
#   Env options : NS_DOMAIN  SSHD_PORT(22)  FASTDNS_PORT(5300)  MTU(1800)
#                 EDNS_SIZE(1800)  WORKERS  FASTDNS_LISTEN(127.0.0.1)
#                 GITHUB_BASE  GITHUB_TOKEN(private repo)  NO_ANIM=1
#   Remove      : bash moded.sh --uninstall
# =============================================================================
set -uo pipefail
export LC_ALL=C.UTF-8 LANG=C.UTF-8

# ----------------------------------------------------------------- CONFIG
GITHUB_BASE="${GITHUB_BASE:-https://raw.githubusercontent.com/wavy07/script4/main/DNSTT%20MODED}"
GITHUB_TOKEN="${GITHUB_TOKEN:-}"
SSHD_PORT="${SSHD_PORT:-22}"
FASTDNS_PORT="${FASTDNS_PORT:-5300}"
FASTDNS_LISTEN="${FASTDNS_LISTEN:-127.0.0.1}"
MTU="${MTU:-1800}"
EDNS_SIZE="${EDNS_SIZE:-1800}"
CORES="$(nproc 2>/dev/null || echo 1)"
WORKERS="${WORKERS:-$(( CORES > 4 ? 4 : CORES ))}"
NS_DOMAIN="${NS_DOMAIN:-}"

FASTDNS_DIR="/etc/Fastdns"
PROXY_BIN="/usr/local/bin/edns-proxy"
SVC_USER="Fastdns"
LOG_FILE="/var/log/Fastdns-install.log"
CONTACT_LINE="${CONTACT_LINE:-Need help? Contact .inc🦜- +255 689000656}"

TOTAL_STEPS=7
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd)" || SCRIPT_DIR="/nonexistent"
TMPD=""
CUR_PCT=0
W=56
T0=$SECONDS

# ----------------------------------------------------------------- COLORS / ANIMATION FLAGS
COLOR=0; ANIM=0
if [[ -t 1 && -z "${NO_COLOR:-}" && "${TERM:-dumb}" != "dumb" ]]; then COLOR=1; fi
if (( COLOR )) && [[ "${NO_ANIM:-0}" != "1" ]]; then ANIM=1; fi

if (( COLOR )); then
  RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'; BLUE=$'\033[0;34m'
  PURPLE=$'\033[0;35m'; CYAN=$'\033[0;36m'; WHITE=$'\033[1;37m'
  BOLD=$'\033[1m'; DIM=$'\033[2m'; NC=$'\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; BLUE=''; PURPLE=''; CYAN=''; WHITE=''; BOLD=''; DIM=''; NC=''
fi
CR=''; EL=''
if (( ANIM )); then CR=$'\r'; EL=$'\033[K'; fi
SPIN_FRAMES=(⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏)

hide_cursor() { if (( ANIM )); then printf '\033[?25l'; fi; return 0; }
show_cursor() { if (( COLOR )); then printf '\033[?25h'; fi; return 0; }
nap()         { if (( ANIM )); then sleep "${1:-0.04}"; fi; return 0; }

# ----------------------------------------------------------------- DRAWING HELPERS
rep() { local s; printf -v s '%*s' "$2" ''; printf '%s' "${s// /$1}"; }
strip_ansi() { printf '%s' "$1" | sed -E 's/\x1b\[[0-9;]*[A-Za-z]//g'; }

_edge() { printf '%s%s%s%s%s\n' "$1" "$2" "$(rep "$3" $((W-2)))" "$4" "$NC"; }
_line() {   # color vchar text
  local plain pad
  plain="$(strip_ansi "$3")"; pad=$(( W - 4 - ${#plain} )); (( pad < 0 )) && pad=0
  printf '%s%s%s %s%*s %s%s%s\n' "$1" "$2" "$NC" "$3" "$pad" "" "$1" "$2" "$NC"
}
_center() { # color vchar text
  local plain total left right
  plain="$(strip_ansi "$3")"; total=$(( W - 2 - ${#plain} )); (( total < 0 )) && total=0
  left=$(( total / 2 )); right=$(( total - left ))
  printf '%s%s%s%*s%s%*s%s%s%s\n' "$1" "$2" "$NC" "$left" "" "$3" "$right" "" "$1" "$2" "$NC"
}
bx_top() { _edge "$1" ┌ ─ ┐; }
bx_mid() { _edge "$1" ├ ─ ┤; }
bx_bot() { _edge "$1" └ ─ ┘; }
bx_row() { _line "$1" │ "$2"; }
dbx_top() { _edge "$1" ╔ ═ ╗; }
dbx_bot() { _edge "$1" ╚ ═ ╝; }
dbx_center() { _center "$1" ║ "$2"; }

log()  { printf '[%s] %s\n' "$(date '+%F %T')" "$*" >>"$LOG_FILE" 2>/dev/null; return 0; }
ok()   { printf '  %s✓%s %s\n' "$GREEN" "$NC" "$*"; log "OK: $*"; }
bad()  { printf '  %s✗%s %s%s%s\n' "$RED" "$NC" "$RED" "$*" "$NC"; log "ERR: $*"; }
warn() { printf '  %s!%s %s%s%s\n' "$YELLOW" "$NC" "$YELLOW" "$*" "$NC"; log "WARN: $*"; }
info() { printf '  %sℹ%s %s%s%s\n' "$CYAN" "$NC" "$CYAN" "$*" "$NC"; }
die()  { show_cursor; echo; bad "$*"; printf '  %sLog: %s%s\n\n' "$DIM" "$LOG_FILE" "$NC"; exit 1; }

# animated progress bar (one line, redrawn in place)
draw_bar() {
  local pct=$1 w=24 f
  f=$(( pct * w / 100 ))
  printf '\r%s│%s  %s%s%s%s%s %3d%%\033[K' "$BLUE" "$NC" "$GREEN" "$(rep '█' "$f")" "$DIM" "$(rep '░' $((w - f)))" "$NC" "$pct"
}
animate_bar() {   # from to
  local p=$1 to=$2
  if (( ANIM )); then
    while (( p < to )); do p=$(( p + 2 )); (( p > to )) && p=$to; draw_bar "$p"; sleep 0.015; done
    draw_bar "$to"; echo
  else
    printf '|  progress %d%%\n' "$to"
  fi
}
step() {   # n title
  local n=$1 pct
  pct=$(( n * 100 / TOTAL_STEPS ))
  printf '\n%s┌─%s %s%sSTEP %s/%s%s  %s%s%s\n' "$BLUE" "$NC" "$CYAN" "$BOLD" "$n" "$TOTAL_STEPS" "$NC" "$WHITE" "$2" "$NC"
  log "STEP $n: $2"
  animate_bar "$CUR_PCT" "$pct"
  CUR_PCT=$pct
  echo "${BLUE}│${NC}"
}
step_end() { printf '%s└─%s %s✓%s Completed\n' "$BLUE" "$NC" "$GREEN" "$NC"; }

# run a command with a spinner; its output goes to the log file
spin_run() {   # label cmd...
  local label="$1"; shift
  local soft="${SPIN_SOFT:-0}" start=$SECONDS rc pid i=0 secs
  log "RUN: $label"
  if (( ANIM )); then
    ( "$@" ) >>"$LOG_FILE" 2>&1 &
    pid=$!
    while kill -0 "$pid" 2>/dev/null; do
      printf '\r  %s%s%s %s %s(%ds)%s\033[K' "$CYAN" "${SPIN_FRAMES[i % 10]}" "$NC" "$label" "$DIM" $(( SECONDS - start )) "$NC"
      i=$(( i + 1 )); sleep 0.08
    done
    wait "$pid"; rc=$?
  else
    ( "$@" ) >>"$LOG_FILE" 2>&1; rc=$?
  fi
  secs=$(( SECONDS - start ))
  if (( rc == 0 )); then
    printf '%s  %s✓%s %s %s(%ds)%s%s\n' "$CR" "$GREEN" "$NC" "$label" "$DIM" "$secs" "$NC" "$EL"
  elif (( soft )); then
    printf '%s  %s!%s %s %s(skipped)%s%s\n' "$CR" "$YELLOW" "$NC" "$label" "$DIM" "$NC" "$EL"
  else
    printf '%s  %s✗%s %s%s%s%s\n' "$CR" "$RED" "$NC" "$RED" "$label" "$NC" "$EL"
    tail -n 8 "$LOG_FILE" 2>/dev/null | sed 's/^/      /'
  fi
  return "$rc"
}
spin_try() { SPIN_SOFT=1 spin_run "$@"; }

# poll a condition with a spinner
spin_wait() {   # label timeout cmd...
  local label="$1" t="$2"; shift 2
  local end=$(( SECONDS + t )) i=0
  while ! "$@" >/dev/null 2>&1; do
    if (( SECONDS >= end )); then
      printf '%s  %s✗%s %s%s%s%s\n' "$CR" "$RED" "$NC" "$RED" "$label" "$NC" "$EL"; return 1
    fi
    if (( ANIM )); then
      printf '\r  %s%s%s %s\033[K' "$CYAN" "${SPIN_FRAMES[i % 10]}" "$NC" "$label"
      i=$(( i + 1 )); sleep 0.1
    else
      sleep 0.4
    fi
  done
  printf '%s  %s✓%s %s%s\n' "$CR" "$GREEN" "$NC" "$label" "$EL"
}

banner() {
  if (( ANIM )); then clear; fi
  echo
  dbx_top "$BLUE";                                                        nap 0.05
  dbx_center "$BLUE" "${CYAN}${BOLD}FASTDNS  MODED  INSTALLER${NC}";       nap 0.05
  dbx_center "$BLUE" "${WHITE}DNSTT + EDNS Proxy (C) + MTU ${MTU}${NC}";   nap 0.05
  dbx_center "$BLUE" "${YELLOW}Ubuntu 20.04-26.04  |  Debian 10-13${NC}";  nap 0.05
  dbx_bot "$BLUE"
  echo
}

cleanup() { show_cursor; if [[ -n "$TMPD" && -d "$TMPD" ]]; then rm -rf "$TMPD"; fi; return 0; }
on_int()  { show_cursor; printf '\n'; bad "Interrupted"; kill $(jobs -p) 2>/dev/null; exit 130; }

# ----------------------------------------------------------------- SYSTEM HELPERS
OS_NAME=""; OS_ID=""; OS_VER=""

detect_os() {
  [[ -r /etc/os-release ]] || die "Cannot detect the operating system (/etc/os-release missing)."
  # shellcheck disable=SC1091
  . /etc/os-release
  OS_ID="${ID:-unknown}"; OS_VER="${VERSION_ID:-}"; OS_NAME="${PRETTY_NAME:-$OS_ID}"
  case " ${ID:-} ${ID_LIKE:-} " in
    *" ubuntu "*|*" debian "*) ;;
    *) die "Unsupported OS: $OS_NAME. This installer supports Ubuntu and Debian (apt based)." ;;
  esac
  command -v apt-get >/dev/null 2>&1 || die "apt-get not found."
  [[ -d /run/systemd/system ]] || die "systemd is required (not running here)."
  local major="${OS_VER%%.*}"
  if [[ "$major" =~ ^[0-9]+$ ]]; then
    if [[ "$OS_ID" == "ubuntu" && "$major" -lt 20 ]]; then warn "Ubuntu $OS_VER is old; continuing anyway."; fi
    if [[ "$OS_ID" == "debian" && "$major" -lt 10 ]]; then warn "Debian $OS_VER is old; continuing anyway."; fi
  fi
}

apt_update()   { DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=120 update -y; }
apt_install()  { DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=120 install -y --no-install-recommends "$@"; }
apt_optional() { apt_install bind9-dnsutils || apt_install dnsutils; }

ssh_unit() { if systemctl list-unit-files 2>/dev/null | grep -q '^ssh\.service'; then echo ssh; else echo sshd; fi; }
udp_listening() { ss -lunH "sport = :$1" 2>/dev/null | grep -q .; }
svc_active()    { systemctl is-active --quiet "$1"; }

get_public_ip() {
  curl -fsS -m 5 https://api.ipify.org 2>/dev/null \
  || curl -fsS -m 5 https://ifconfig.me 2>/dev/null \
  || hostname -I 2>/dev/null | awk '{print $1}'
}
detect_ip_to_file() { get_public_ip > "$TMPD/ip"; }

valid_domain() { [[ "$1" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$ ]]; }

ask_domain() {
  while ! valid_domain "$NS_DOMAIN"; do
    if [[ -n "$NS_DOMAIN" ]]; then bad "'$NS_DOMAIN' is not a valid domain name"; fi
    if [[ ! -r /dev/tty ]]; then
      die "No terminal available. Run:  NS_DOMAIN=t.example.com bash $0"
    fi
    echo "${WHITE}${BOLD}Enter your tunnel nameserver domain${NC}"
    bx_top "$CYAN"
    bx_row "$CYAN" "${YELLOW}Example:${NC} t.yourdomain.com"
    bx_row "$CYAN" "${DIM}(the NS record of this name points to this server)${NC}"
    bx_bot "$CYAN"
    printf '%s%sNameserver: %s' "$WHITE" "$BOLD" "$NC"
    read -r NS_DOMAIN </dev/tty || die "Input cancelled."
    NS_DOMAIN="${NS_DOMAIN//[[:space:]]/}"
  done
}

# ----------------------------------------------------------------- DOWNLOAD / VERIFY
dl() {   # url dest
  local url="$1" dest="$2"
  if [[ -n "$GITHUB_TOKEN" ]]; then
    curl -fsSL --retry 3 --connect-timeout 10 -H "Authorization: token $GITHUB_TOKEN" "$url" -o "$dest"
  else
    curl -fsSL --retry 3 --connect-timeout 10 "$url" -o "$dest" || wget -q -O "$dest" "$url"
  fi
}

fetch_asset() {   # name  -> $FASTDNS_DIR/name (atomic, only replaced on success)
  local name="$1" dest="$FASTDNS_DIR/$1"
  rm -f "$dest.new"
  if [[ -s "$SCRIPT_DIR/$name" && "$SCRIPT_DIR" != "$FASTDNS_DIR" ]]; then
    cp -f "$SCRIPT_DIR/$name" "$dest.new"
  else
    dl "$GITHUB_BASE/$name" "$dest.new" || { rm -f "$dest.new"; return 1; }
  fi
  [[ -s "$dest.new" ]] || { rm -f "$dest.new"; return 1; }
  mv -f "$dest.new" "$dest"
}

elf_ok() {   # file -> is an ELF binary that matches this CPU
  local f="$1" m want
  [[ "$(head -c4 "$f" 2>/dev/null | tail -c3)" == "ELF" ]] || return 1
  m="$(od -An -tx1 -j18 -N1 "$f" 2>/dev/null | tr -d ' \n')"
  case "$(uname -m)" in
    x86_64|amd64)  want="3e" ;;
    aarch64|arm64) want="b7" ;;
    armv7l|armv6l) want="28" ;;
    i?86)          want="03" ;;
    *)             return 0 ;;
  esac
  [[ "$m" == "$want" ]]
}

fetch_binary() {
  fetch_asset dnstt-server || return 1
  if ! elf_ok "$FASTDNS_DIR/dnstt-server"; then
    echo "dnstt-server is not a valid binary for $(uname -m)"; rm -f "$FASTDNS_DIR/dnstt-server"; return 1
  fi
  chmod 755 "$FASTDNS_DIR/dnstt-server"
}

build_dnstt_from_source() {
  apt_install golang-go git ca-certificates
  GOBIN="$FASTDNS_DIR" GOPATH="$TMPD/gopath" HOME="$TMPD" \
    go install www.bamsoftware.com/git/dnstt.git/dnstt-server@latest
  chmod 755 "$FASTDNS_DIR/dnstt-server"
}

gen_keys() {
  rm -f "$FASTDNS_DIR/server.key" "$FASTDNS_DIR/server.pub"
  "$FASTDNS_DIR/dnstt-server" -gen-key -privkey-file "$FASTDNS_DIR/server.key" -pubkey-file "$FASTDNS_DIR/server.pub"
}

fetch_keys() { fetch_asset server.key && fetch_asset server.pub; }

# ----------------------------------------------------------------- EDNS PROXY (C SOURCE)
write_proxy_source() {
cat > "$1" <<'CEOF'
/*
 * edns-proxy.c - UDP DNS proxy that rewrites the EDNS0 UDP payload size.
 *
 *   resolver -> :53 [edns-proxy] -> 127.0.0.1:5300 [dnstt-server]
 *
 * Queries : the OPT record's advertised payload size is raised to -s (1800),
 *           so dnstt-server is allowed to send larger responses (more
 *           payload per query = faster tunnel).
 * Replies : the OPT payload size is restored to what the resolver sent.
 *
 * Multi-process (SO_REUSEPORT), epoll based, transaction-ID remapping.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define BUF_SZ    4096
#define TABLE_SZ  65536
#define ENTRY_TTL 10
#define BATCH     256

struct entry {
    struct sockaddr_storage addr;
    socklen_t alen;
    uint16_t orig_id;
    uint16_t orig_size;
    uint8_t  has_opt;
    uint8_t  used;
    time_t   ts;
};

static volatile sig_atomic_t g_stop = 0;
static void on_term(int s) { (void)s; g_stop = 1; }

static inline uint16_t rd16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static inline void wr16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v & 0xff; }

/* Skip a (possibly compressed) DNS name. Returns offset after it, or -1. */
static int skip_name(const uint8_t *p, int len, int off)
{
    int steps = 0;
    while (off < len) {
        uint8_t c = p[off];
        if (c == 0) return off + 1;
        if ((c & 0xC0) == 0xC0) return (off + 2 <= len) ? off + 2 : -1;
        if (c & 0xC0) return -1;
        off += 1 + c;
        if (++steps > 128) return -1;
    }
    return -1;
}

/* Returns the offset of the OPT record's CLASS field (= UDP payload size), or -1. */
static int find_opt(const uint8_t *p, int len)
{
    if (len < 12) return -1;
    int qd = rd16(p + 4), an = rd16(p + 6), ns = rd16(p + 8), ar = rd16(p + 10);
    int off = 12;

    for (int i = 0; i < qd; i++) {
        off = skip_name(p, len, off);
        if (off < 0 || off + 4 > len) return -1;
        off += 4;
    }
    int total = an + ns + ar;
    for (int i = 0; i < total; i++) {
        int name_off = off;
        off = skip_name(p, len, off);
        if (off < 0 || off + 10 > len) return -1;
        uint16_t type  = rd16(p + off);
        uint16_t rdlen = rd16(p + off + 8);
        if (i >= an + ns && type == 41 && p[name_off] == 0)
            return off + 2;
        off += 10;
        if (off + rdlen > len) return -1;
        off += rdlen;
    }
    return -1;
}

static int make_listener(int port)
{
    int one = 1, zero = 0, bs = 8 << 20;
    int fd = socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (fd >= 0) {
        struct sockaddr_in6 a;
        memset(&a, 0, sizeof a);
        a.sin6_family = AF_INET6;
        a.sin6_addr = in6addr_any;
        a.sin6_port = htons(port);
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof zero);
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one);
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bs, sizeof bs);
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bs, sizeof bs);
        if (bind(fd, (struct sockaddr *)&a, sizeof a) == 0) return fd;
        close(fd);
    }
    fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (fd < 0) return -1;
    struct sockaddr_in a4;
    memset(&a4, 0, sizeof a4);
    a4.sin_family = AF_INET;
    a4.sin_addr.s_addr = htonl(INADDR_ANY);
    a4.sin_port = htons(port);
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one);
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bs, sizeof bs);
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bs, sizeof bs);
    if (bind(fd, (struct sockaddr *)&a4, sizeof a4) < 0) { close(fd); return -1; }
    return fd;
}

static void worker(int port, const struct sockaddr_in *up, int edns_size)
{
    signal(SIGTERM, SIG_DFL);
    signal(SIGINT, SIG_DFL);

    int lfd = make_listener(port);
    if (lfd < 0) { perror("listen"); _exit(1); }

    int ufd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (ufd < 0 || connect(ufd, (const struct sockaddr *)up, sizeof *up) < 0) {
        perror("upstream"); _exit(1);
    }
    int bs = 8 << 20;
    setsockopt(ufd, SOL_SOCKET, SO_RCVBUF, &bs, sizeof bs);
    setsockopt(ufd, SOL_SOCKET, SO_SNDBUF, &bs, sizeof bs);

    struct entry *table = calloc(TABLE_SZ, sizeof *table);
    if (!table) _exit(1);
    uint16_t next = (uint16_t)(getpid() * 40503u);

    int ep = epoll_create1(0);
    struct epoll_event ev;
    memset(&ev, 0, sizeof ev);
    ev.events = EPOLLIN;
    ev.data.fd = lfd; epoll_ctl(ep, EPOLL_CTL_ADD, lfd, &ev);
    ev.data.fd = ufd; epoll_ctl(ep, EPOLL_CTL_ADD, ufd, &ev);

    uint8_t buf[BUF_SZ];
    struct epoll_event evs[2];

    for (;;) {
        int k = epoll_wait(ep, evs, 2, 1000);
        if (k < 0) { if (errno == EINTR) continue; break; }
        time_t now = time(NULL);

        for (int i = 0; i < k; i++) {
            if (evs[i].data.fd == lfd) {
                /* ---- resolver -> dnstt-server ---- */
                for (int j = 0; j < BATCH; j++) {
                    struct sockaddr_storage ss;
                    socklen_t sl = sizeof ss;
                    ssize_t n = recvfrom(lfd, buf, BUF_SZ, 0, (struct sockaddr *)&ss, &sl);
                    if (n < 0) break;
                    if (n < 12 || (buf[2] & 0x80)) continue;   /* not a query */

                    uint16_t slot = next++;
                    struct entry *e = &table[slot];
                    e->addr = ss; e->alen = sl;
                    e->orig_id = rd16(buf);
                    e->ts = now; e->used = 1;

                    int o = find_opt(buf, (int)n);
                    if (o >= 0) {
                        e->has_opt = 1;
                        e->orig_size = rd16(buf + o);
                        if (e->orig_size < edns_size) wr16(buf + o, (uint16_t)edns_size);
                    } else {
                        e->has_opt = 0;
                    }
                    wr16(buf, slot);
                    send(ufd, buf, (size_t)n, 0);
                }
            } else {
                /* ---- dnstt-server -> resolver ---- */
                for (int j = 0; j < BATCH; j++) {
                    ssize_t n = recv(ufd, buf, BUF_SZ, 0);
                    if (n < 0) break;
                    if (n < 12 || !(buf[2] & 0x80)) continue;   /* not a response */

                    struct entry *e = &table[rd16(buf)];
                    if (!e->used || now - e->ts > ENTRY_TTL) continue;

                    wr16(buf, e->orig_id);
                    if (e->has_opt) {
                        int o = find_opt(buf, (int)n);
                        if (o >= 0) wr16(buf + o, e->orig_size);
                    }
                    sendto(lfd, buf, (size_t)n, 0, (struct sockaddr *)&e->addr, e->alen);
                    e->used = 0;
                }
            }
        }
    }
    _exit(0);
}

int main(int argc, char **argv)
{
    int port = 53, size = 1800, workers = 2, opt;
    const char *upstr = "127.0.0.1:5300";

    while ((opt = getopt(argc, argv, "l:u:s:w:")) != -1) {
        switch (opt) {
        case 'l': port = atoi(optarg); break;
        case 'u': upstr = optarg; break;
        case 's': size = atoi(optarg); break;
        case 'w': workers = atoi(optarg); break;
        default:
            fprintf(stderr, "usage: %s [-l port] [-u host:port] [-s edns_size] [-w workers]\n", argv[0]);
            return 2;
        }
    }
    if (size < 512) size = 512;
    if (size > 4096) size = 4096;
    if (workers < 1) workers = 1;
    if (workers > 16) workers = 16;

    char host[64];
    const char *colon = strrchr(upstr, ':');
    if (!colon || (size_t)(colon - upstr) >= sizeof host) { fprintf(stderr, "bad -u\n"); return 2; }
    memcpy(host, upstr, (size_t)(colon - upstr));
    host[colon - upstr] = 0;

    struct sockaddr_in up;
    memset(&up, 0, sizeof up);
    up.sin_family = AF_INET;
    up.sin_port = htons((uint16_t)atoi(colon + 1));
    if (inet_pton(AF_INET, host, &up.sin_addr) != 1) { fprintf(stderr, "bad upstream host\n"); return 2; }

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_term;           /* no SA_RESTART: wait() must be interruptible */
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    fprintf(stderr, "edns-proxy: :%d -> %s, edns=%d, workers=%d\n", port, upstr, size, workers);

    for (int i = 0; i < workers; i++) {
        pid_t p = fork();
        if (p == 0) worker(port, &up, size);
        if (p < 0) { perror("fork"); return 1; }
    }
    while (!g_stop) {
        pid_t p = wait(NULL);
        if (g_stop) break;
        if (p > 0) {                   /* respawn a dead worker */
            sleep(1);
            if (fork() == 0) worker(port, &up, size);
        } else if (errno != EINTR) {
            break;
        }
    }
    return 0;
}
CEOF
}

build_proxy() {
  write_proxy_source "$TMPD/edns-proxy.c"
  gcc -O2 -Wall -o "$PROXY_BIN.new" "$TMPD/edns-proxy.c" \
    && mv -f "$PROXY_BIN.new" "$PROXY_BIN" \
    && chmod 755 "$PROXY_BIN"
}

# ----------------------------------------------------------------- TUNING
write_sysctl() {
  modprobe tcp_bbr 2>/dev/null || true
  local cc=""
  if grep -qw bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null; then
    cc="net.ipv4.tcp_congestion_control = bbr"
  fi
  cat > /etc/sysctl.d/99-Fastdns.conf <<EOF
# --- SlowDNS performance tuning ---
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.rmem_default = 8388608
net.core.wmem_default = 8388608
net.core.netdev_max_backlog = 50000
net.core.somaxconn = 8192
net.core.default_qdisc = fq
net.ipv4.udp_mem = 262144 524288 1048576
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384
net.ipv4.tcp_rmem = 4096 262144 33554432
net.ipv4.tcp_wmem = 4096 262144 33554432
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_fastopen = 3
# MTU ${MTU} means DNS replies fragment at IP level: give reassembly more room
net.ipv4.ipfrag_high_thresh = 8388608
net.ipv4.ipfrag_low_thresh = 6291456
net.ipv4.ipfrag_time = 15
${cc}
EOF
  sysctl -q -p /etc/sysctl.d/99-Fastdns.conf || true   # containers may reject some keys
  return 0
}

tune_ssh() {
  # Safe drop-in only: does NOT touch your root-login / password settings.
  [[ -d /etc/ssh/sshd_config.d ]] || { echo "no sshd_config.d, skipping"; return 1; }
  grep -Eqi '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/' /etc/ssh/sshd_config \
    || { echo "sshd_config has no Include line, skipping"; return 1; }
  cat > /etc/ssh/sshd_config.d/10-Fastdns.conf <<'EOF'
# SlowDNS: keep tunnels alive and allow many sessions
TCPKeepAlive yes
ClientAliveInterval 60
ClientAliveCountMax 3
AllowTcpForwarding yes
MaxSessions 100
MaxStartups 100:30:200
UseDNS no
EOF
  mkdir -p /run/sshd
  if sshd -t 2>/dev/null; then
    systemctl reload "$(ssh_unit)" 2>/dev/null || true
  else
    rm -f /etc/ssh/sshd_config.d/10-Fastdns.conf
    echo "sshd config test failed; drop-in removed"
    return 1
  fi
}

# ----------------------------------------------------------------- SERVICES
write_units() {
  local mtu_opt=""
  if "$FASTDNS_DIR/dnstt-server" -h 2>&1 | grep -q -- '-mtu'; then
    mtu_opt="-mtu ${MTU}"
  else
    echo "dnstt-server has no -mtu flag; relying on the EDNS proxy only"
  fi

  cat > /etc/systemd/system/server-sldns.service <<EOF
[Unit]
Description=SlowDNS Server (dnstt)
After=network-online.target $(ssh_unit).service
Wants=network-online.target

[Service]
Type=simple
User=${SVC_USER}
Group=${SVC_USER}
WorkingDirectory=${FASTDNS_DIR}
ExecStart=${FASTDNS_DIR}/dnstt-server -udp ${FASTDNS_LISTEN}:${FASTDNS_PORT} ${mtu_opt} -privkey-file ${FASTDNS_DIR}/server.key ${NS_DOMAIN} 127.0.0.1:${SSHD_PORT}
Restart=always
RestartSec=3
LimitNOFILE=1048576
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF

  cat > /etc/systemd/system/edns-proxy.service <<EOF
[Unit]
Description=EDNS Proxy for SlowDNS (C)
After=server-sldns.service
Wants=server-sldns.service

[Service]
Type=simple
User=${SVC_USER}
Group=${SVC_USER}
ExecStart=${PROXY_BIN} -l 53 -u 127.0.0.1:${FASTDNS_PORT} -s ${EDNS_SIZE} -w ${WORKERS}
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
Restart=always
RestartSec=3
LimitNOFILE=1048576
Nice=-5
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
}

# ----------------------------------------------------------------- NETWORK
free_port_53() {
  if svc_active systemd-resolved; then
    mkdir -p /etc/systemd/resolved.conf.d
    printf '[Resolve]\nDNSStubListener=no\n' > /etc/systemd/resolved.conf.d/10-Fastdns.conf
    if [[ -L /etc/resolv.conf ]] && readlink -f /etc/resolv.conf | grep -q 'stub-resolv.conf'; then
      ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
    fi
    systemctl restart systemd-resolved
    sleep 1
  fi
  if udp_listening 53; then
    local owner
    owner="$(ss -lunpH 'sport = :53' | grep -o 'users:(("[^"]*"' | head -1 | cut -d'"' -f2)"
    echo "UDP port 53 is already used by: ${owner:-unknown}"
    echo "Stop it first, e.g.:  systemctl disable --now ${owner:-<service>}"
    return 1
  fi
}

open_firewall() {
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q 'Status: active'; then
    ufw allow 53/udp
  fi
  if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port=53/udp && firewall-cmd --reload
  fi
  if command -v iptables >/dev/null 2>&1; then
    iptables -C INPUT -p udp --dport 53 -j ACCEPT 2>/dev/null || iptables -I INPUT -p udp --dport 53 -j ACCEPT || true
  fi
  if command -v ip6tables >/dev/null 2>&1; then
    ip6tables -C INPUT -p udp --dport 53 -j ACCEPT 2>/dev/null || ip6tables -I INPUT -p udp --dport 53 -j ACCEPT || true
  fi
  if command -v netfilter-persistent >/dev/null 2>&1; then netfilter-persistent save || true; fi
  return 0
}

dns_roundtrip()  { dig +time=2 +tries=1 @127.0.0.1 "probe.${NS_DOMAIN}" TXT 2>/dev/null | grep -q 'status:'; }
spin_wait_dns()  { local i; for i in 1 2 3 4 5; do dns_roundtrip && return 0; sleep 1; done; return 1; }

# ----------------------------------------------------------------- UNINSTALL
do_uninstall() {
  (( EUID == 0 )) || die "Run as root."
  banner
  echo "${WHITE}${BOLD}Removing SlowDNS...${NC}"
  systemctl disable --now edns-proxy server-sldns 2>/dev/null
  if [[ -s "$FASTDNS_DIR/server.key" ]]; then
    mkdir -p /root/Fastdns-keys-backup && cp -f "$FASTDNS_DIR"/server.key "$FASTDNS_DIR"/server.pub /root/Fastdns-keys-backup/ 2>/dev/null
    ok "Keys backed up to /root/Fastdns-keys-backup"
  fi
  rm -f /etc/systemd/system/server-sldns.service /etc/systemd/system/edns-proxy.service "$PROXY_BIN" \
        /etc/sysctl.d/99-Fastdns.conf /etc/ssh/sshd_config.d/10-Fastdns.conf
  rm -rf "$FASTDNS_DIR"
  if [[ -f /etc/systemd/resolved.conf.d/10-Fastdns.conf ]]; then
    rm -f /etc/systemd/resolved.conf.d/10-Fastdns.conf
    if [[ "$(readlink /etc/resolv.conf)" == "/run/systemd/resolve/resolv.conf" ]]; then
      ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
    fi
    systemctl restart systemd-resolved 2>/dev/null
  fi
  systemctl daemon-reload; sysctl --system >/dev/null 2>&1
  systemctl reload "$(ssh_unit)" 2>/dev/null
  ok "SlowDNS removed"
  exit 0
}

# ----------------------------------------------------------------- SUMMARY + MENU
show_summary() {
  local ip="$1" elapsed=$(( SECONDS - T0 ))
  echo
  dbx_top "$GREEN"
  dbx_center "$GREEN" "${WHITE}${BOLD}INSTALLATION COMPLETE${NC}"
  dbx_center "$GREEN" "${WHITE}Finished in ${elapsed}s  |  SlowDNS + EDNS Proxy${NC}"
  dbx_bot "$GREEN"

  echo; bx_top "$CYAN"
  bx_row "$CYAN" "${WHITE}${BOLD}SERVER INFORMATION${NC}"; bx_mid "$CYAN"
  bx_row "$CYAN" "${YELLOW}●${NC} Server IP    : ${WHITE}${ip}${NC}"
  bx_row "$CYAN" "${YELLOW}●${NC} Nameserver   : ${WHITE}${NS_DOMAIN}${NC}"
  bx_row "$CYAN" "${YELLOW}●${NC} SSH port     : ${WHITE}${SSHD_PORT}${NC}"
  bx_row "$CYAN" "${YELLOW}●${NC} EDNS proxy   : ${WHITE}UDP 53  (EDNS ${EDNS_SIZE})${NC}"
  bx_row "$CYAN" "${YELLOW}●${NC} SlowDNS      : ${WHITE}${FASTDNS_LISTEN}:${FASTDNS_PORT}  (MTU ${MTU})${NC}"
  bx_row "$CYAN" "${YELLOW}●${NC} OS           : ${WHITE}${OS_NAME}${NC}"
  bx_bot "$CYAN"

  echo; bx_top "$CYAN"
  bx_row "$CYAN" "${WHITE}${BOLD}DNS RECORDS TO CREATE${NC}"; bx_mid "$CYAN"
  bx_row "$CYAN" "${YELLOW}A  ${NC} ns1.yourdomain.com  ->  ${WHITE}${ip}${NC}"
  bx_row "$CYAN" "${YELLOW}NS ${NC} ${NS_DOMAIN}"
  bx_row "$CYAN" "      ->  ns1.yourdomain.com"
  bx_bot "$CYAN"

  echo; bx_top "$CYAN"
  bx_row "$CYAN" "${WHITE}${BOLD}CLIENT EXAMPLE${NC}"; bx_mid "$CYAN"
  bx_row "$CYAN" "${GREEN}./dnstt-client -udp 8.8.8.8:53 \\${NC}"
  bx_row "$CYAN" "${GREEN}  -pubkey-file server.pub \\${NC}"
  bx_row "$CYAN" "${GREEN}  ${NS_DOMAIN} 127.0.0.1:1080${NC}"
  bx_bot "$CYAN"

  echo; bx_top "$CYAN"
  bx_row "$CYAN" "${WHITE}${BOLD}MANAGE${NC}"; bx_mid "$CYAN"
  bx_row "$CYAN" "${GREEN}systemctl restart server-sldns edns-proxy${NC}"
  bx_row "$CYAN" "${GREEN}journalctl -u server-sldns -f${NC}"
  bx_row "$CYAN" "${GREEN}ss -ulpn | grep -E ':53 |:${FASTDNS_PORT} '${NC}"
  bx_bot "$CYAN"

  if [[ -s "$FASTDNS_DIR/server.pub" ]]; then
    echo; echo "${WHITE}${BOLD}PUBLIC KEY (give this to clients):${NC}"
    echo "${GREEN}$(head -1 "$FASTDNS_DIR/server.pub")${NC}"
  fi
  echo
  echo "${DIM}Tuning raises limits for speed, but real DNS-tunnel throughput depends on${NC}"
  echo "${DIM}the resolver and network path; 20 MB/s is not guaranteed.${NC}"
  if [[ -n "$CONTACT_LINE" ]]; then echo; echo "${YELLOW}${BOLD}${CONTACT_LINE}${NC}"; fi
}

post_menu() {
  [[ -r /dev/tty ]] || return 0
  local opt
  while true; do
    echo; bx_top "$CYAN"
    bx_row "$CYAN" "${WHITE}${BOLD}POST-INSTALLATION OPTIONS${NC}"; bx_mid "$CYAN"
    bx_row "$CYAN" "${YELLOW}1.${NC} View service status"
    bx_row "$CYAN" "${YELLOW}2.${NC} Check listening ports"
    bx_row "$CYAN" "${YELLOW}3.${NC} Restart all services"
    bx_row "$CYAN" "${YELLOW}4.${NC} View installation log"
    bx_row "$CYAN" "${YELLOW}5.${NC} Test DNS functionality"
    bx_row "$CYAN" "${YELLOW}6.${NC} Show public key"
    bx_row "$CYAN" "${YELLOW}7.${NC} Exit"
    bx_bot "$CYAN"
    printf '%s%sSelect option [1-7]: %s' "$WHITE" "$BOLD" "$NC"
    read -r opt </dev/tty || break
    echo
    case "$opt" in
      1) systemctl status server-sldns edns-proxy --no-pager -l ;;
      2) echo "${WHITE}UDP:${NC}"; ss -ulpn | grep -E ':53 |:'"$FASTDNS_PORT"' '
         echo "${WHITE}TCP (ssh):${NC}"; ss -tlnp | grep -E ":${SSHD_PORT} " ;;
      3) systemctl restart server-sldns edns-proxy; sleep 2
         if svc_active server-sldns && svc_active edns-proxy; then ok "Services restarted"; else warn "A service failed to restart"; fi ;;
      4) tail -n 40 "$LOG_FILE" ;;
      5) if command -v dig >/dev/null 2>&1; then
           if dns_roundtrip; then ok "Proxy answered a DNS query"; else warn "No DNS answer from 127.0.0.1:53"; fi
         else warn "dig is not installed (apt install bind9-dnsutils)"; fi ;;
      6) cat "$FASTDNS_DIR/server.pub" ;;
      7|q|Q|"") break ;;
      *) warn "Invalid option" ;;
    esac
  done
  echo; echo "${GREEN}${BOLD}Done. $(date)${NC}"
}

# ----------------------------------------------------------------- MAIN
main() {
  case "${1:-}" in
    --uninstall) do_uninstall ;;
    -h|--help)   sed -n '2,20p' "${BASH_SOURCE[0]:-$0}" 2>/dev/null | sed 's/^# \{0,1\}//'; exit 0 ;;
    "")          ;;
    *)           NS_DOMAIN="${NS_DOMAIN:-$1}" ;;
  esac

  if (( EUID != 0 )); then bad "Please run this script as root (sudo -i  or  su -)."; exit 1; fi
  mkdir -p "$(dirname "$LOG_FILE")"; : > "$LOG_FILE"; chmod 600 "$LOG_FILE"
  TMPD="$(mktemp -d)"
  trap cleanup EXIT
  trap on_int INT TERM
  local v
  for v in SSHD_PORT FASTDNS_PORT MTU EDNS_SIZE WORKERS; do
    [[ "${!v}" =~ ^[0-9]+$ ]] || die "$v must be a number (got '${!v}')"
  done

  hide_cursor
  banner
  detect_os
  ok "Detected ${OS_NAME} (${OS_ID} ${OS_VER:-rolling}) on $(uname -m)"
  show_cursor
  ask_domain
  hide_cursor
  spin_try "Detecting server IP address" detect_ip_to_file
  SERVER_IP="$(cat "$TMPD/ip" 2>/dev/null)"; SERVER_IP="${SERVER_IP:-unknown}"
  ok "Server IP: ${WHITE}${BOLD}${SERVER_IP}${NC}"

  # ---------------------------------------------------------------- STEP 1
  step 1 "System check & dependencies"
  spin_run "Updating package lists" apt_update || die "apt update failed"
  spin_run "Installing gcc, curl, iproute2, openssh-server" \
    apt_install gcc libc6-dev curl ca-certificates iproute2 procps psmisc openssh-server \
    || die "Package installation failed"
  spin_try "Installing DNS test tools (dig)" apt_optional
  id "$SVC_USER" >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin "$SVC_USER"
  systemctl enable --now "$(ssh_unit)" >/dev/null 2>&1
  ok "Service account '${SVC_USER}' and SSH ready"
  step_end

  # ---------------------------------------------------------------- STEP 2
  step 2 "Fetching SlowDNS binary & keys"
  systemctl stop edns-proxy server-sldns >/dev/null 2>&1
  mkdir -p "$FASTDNS_DIR"
  info "Source: ${GITHUB_BASE}"
  if ! spin_try "Downloading dnstt-server" fetch_binary; then
    if [[ -x "$FASTDNS_DIR/dnstt-server" ]]; then
      warn "Download failed, keeping the existing binary"
    else
      warn "Repo download failed (private repo? set GITHUB_TOKEN). Trying a source build..."
      spin_run "Building dnstt-server from source (Go)" build_dnstt_from_source \
        || die "No dnstt-server binary available."
    fi
  fi
  timeout 5 "$FASTDNS_DIR/dnstt-server" -h >/dev/null 2>&1; rc=$?
  if (( rc == 126 || rc == 127 )); then die "dnstt-server cannot run on this machine ($(uname -m))."; fi
  if spin_try "Downloading server.key & server.pub" fetch_keys; then
    ok "Keys loaded from repo"
  elif [[ -s "$FASTDNS_DIR/server.key" && -s "$FASTDNS_DIR/server.pub" ]]; then
    warn "Repo keys unavailable, keeping the existing keypair"
  else
    spin_run "Generating a new keypair" gen_keys || die "Key generation failed"
    warn "New keys generated: give clients the new server.pub"
  fi
  chmod 600 "$FASTDNS_DIR/server.key"; chmod 644 "$FASTDNS_DIR/server.pub"
  step_end

  # ---------------------------------------------------------------- STEP 3
  step 3 "Compiling the EDNS proxy (C)"
  spin_run "Compiling edns-proxy (gcc -O2)" build_proxy || die "Compilation failed (see log)"
  ok "Installed ${PROXY_BIN}  (EDNS ${EDNS_SIZE}, ${WORKERS} worker(s))"
  step_end

  # ---------------------------------------------------------------- STEP 4
  step 4 "Performance tuning"
  spin_run "Applying kernel network tuning (BBR, buffers, frag)" write_sysctl
  spin_try "Optimising SSH for many tunnel sessions" tune_ssh
  step_end

  # ---------------------------------------------------------------- STEP 5
  step 5 "Creating system services"
  chown -R "$SVC_USER:$SVC_USER" "$FASTDNS_DIR"
  spin_run "Writing server-sldns & edns-proxy units" write_units || die "Could not write services"
  step_end

  # ---------------------------------------------------------------- STEP 6
  step 6 "Network & firewall"
  spin_run "Freeing UDP port 53" free_port_53 || die "UDP port 53 is busy (see the message above)"
  spin_run "Opening UDP 53 in the firewall" open_firewall
  step_end

  # ---------------------------------------------------------------- STEP 7
  step 7 "Starting & verifying"
  systemctl enable server-sldns edns-proxy >/dev/null 2>&1
  systemctl restart server-sldns
  spin_wait "SlowDNS listening on ${FASTDNS_LISTEN}:${FASTDNS_PORT}" 15 udp_listening "$FASTDNS_PORT" \
    || { journalctl -u server-sldns -n 15 --no-pager 2>/dev/null | sed 's/^/      /'; die "server-sldns failed to start"; }
  systemctl restart edns-proxy
  spin_wait "EDNS proxy listening on UDP 53" 15 udp_listening 53 \
    || { journalctl -u edns-proxy -n 15 --no-pager 2>/dev/null | sed 's/^/      /'; die "edns-proxy failed to start"; }
  if svc_active server-sldns && svc_active edns-proxy; then ok "Both services are active"; else warn "A service is not active"; fi
  if command -v dig >/dev/null 2>&1; then
    spin_try "DNS round-trip through the proxy" spin_wait_dns
  fi
  step_end

  show_cursor
  show_summary "$SERVER_IP"
  post_menu
}

if [[ -z "${FASTDNS_SOURCE_ONLY:-}" ]]; then
  main "$@"
fi
