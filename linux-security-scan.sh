#!/usr/bin/env bash
#
# linux-security-scan.sh - Hybrid Linux security scanner
#
# A self-contained host security auditor for Debian/Ubuntu and Fedora/RHEL
# families. It runs native checks using standard OS commands (no mandatory
# installs, works offline) and, when present, also uses external tools
# (Lynis, Trivy/Grype, rkhunter, chkrootkit, AIDE, oscap via SCAP-Scan.sh)
# to deepen the results. Findings are printed and written as text/JSON/HTML.
#
# Coverage: configuration hardening, accounts & auth, network exposure,
# vulnerability/CVE, and rootkit/file-integrity.
#
# Local host only. Best run as root; many checks degrade without it.
#
# NOTE: -e (errexit) is intentionally NOT set: a security scan runs many probe
# commands whose non-zero exit is normal (no match, tool absent). We use
# nounset + pipefail and guard explicitly instead.

set -uo pipefail

readonly VERSION="1.0.0"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
readonly SCRIPT_DIR

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
OUTPUT_DIR="./SecurityScan_Reports"
FORMAT="all"                 # text | json | html | all
ONLY=""                      # comma list of groups to run
SKIP=""                      # comma list of groups to skip
USE_EXTERNAL=1               # hybrid: use external tools if installed
DEEP=0                       # enable slow/heavy scans (full-fs walk, trivy, rkhunter, aide --check)
LOG_FILE=""

readonly ALL_GROUPS="hardening accounts network vuln rootkit integrity"

# ---------------------------------------------------------------------------
# Colors / logging
# ---------------------------------------------------------------------------
if [[ -t 1 ]]; then
    C_RESET=$'\033[0m'; C_RED=$'\033[31m'; C_GREEN=$'\033[32m'
    C_YELLOW=$'\033[33m'; C_BLUE=$'\033[34m'; C_CYAN=$'\033[36m'; C_DIM=$'\033[2m'
else
    C_RESET=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_CYAN=""; C_DIM=""
fi

log() {
    local level="$1"; shift
    local ts; ts="$(date '+%Y-%m-%d %H:%M:%S')"
    local line="${ts} - [${level}] - $*"
    printf '%s\n' "$line" >&2
    [[ -n "$LOG_FILE" ]] && printf '%s\n' "$line" >>"$LOG_FILE" 2>/dev/null || true
}

die() { printf '%sERROR: %s%s\n' "$C_RED" "$*" "$C_RESET" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Findings framework
# ---------------------------------------------------------------------------
declare -a FINDINGS=()                 # entries: "SEV|CATEGORY|TITLE|DETAIL"
declare -A SEV_COUNT=( [HIGH]=0 [MEDIUM]=0 [LOW]=0 [INFO]=0 [PASS]=0 )

add_finding() {
    local sev="$1" category="$2" title="$3" detail="${4:-}"
    FINDINGS+=("${sev}|${category}|${title}|${detail}")
    SEV_COUNT[$sev]=$(( ${SEV_COUNT[$sev]:-0} + 1 ))
    local color=""
    case "$sev" in
        HIGH)   color="$C_RED" ;;
        MEDIUM) color="$C_YELLOW" ;;
        LOW)    color="$C_BLUE" ;;
        PASS)   color="$C_GREEN" ;;
        INFO)   color="$C_DIM" ;;
    esac
    printf '%s[%-6s]%s %s: %s%s\n' "$color" "$sev" "$C_RESET" "$category" "$title" \
        "${detail:+ ${C_DIM}(${detail})${C_RESET}}" >&2
    [[ -n "$LOG_FILE" ]] && printf '[%s] %s: %s%s\n' "$sev" "$category" "$title" "${detail:+ ($detail)}" >>"$LOG_FILE" 2>/dev/null || true
    return 0
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
have_cmd() { command -v "$1" >/dev/null 2>&1; }

group_enabled() {
    local g="$1"
    if [[ -n "$ONLY" ]]; then [[ ",${ONLY}," == *",${g},"* ]] && return 0 || return 1; fi
    if [[ -n "$SKIP" ]]; then [[ ",${SKIP}," == *",${g},"* ]] && return 1 || return 0; fi
    return 0
}

OS_ID=""; OS_LIKE=""; OS_PRETTY=""
read_os() {
    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        OS_ID="${ID:-}"; OS_LIKE="${ID_LIKE:-}"; OS_PRETTY="${PRETTY_NAME:-}"
    fi
}

is_debian_like() { [[ "$OS_ID" == debian || "$OS_ID" == ubuntu || "$OS_LIKE" == *debian* ]]; }
is_rhel_like()   { [[ "$OS_ID" == fedora || "$OS_ID" == rhel || "$OS_ID" == centos || "$OS_LIKE" == *rhel* || "$OS_LIKE" == *fedora* ]]; }

sysctl_val() {
    local key="$1"
    if have_cmd sysctl; then sysctl -n "$key" 2>/dev/null && return 0; fi
    cat "/proc/sys/${key//.//}" 2>/dev/null || true
}

json_escape() {
    local s="${1:-}"
    s="${s//\\/\\\\}"; s="${s//\"/\\\"}"
    s="${s//$'\t'/\\t}"; s="${s//$'\r'/}"; s="${s//$'\n'/\\n}"
    printf '%s' "$s"
}

html_escape() {
    local s="${1:-}"
    s="${s//&/&amp;}"; s="${s//</&lt;}"; s="${s//>/&gt;}"
    printf '%s' "$s"
}

# ---------------------------------------------------------------------------
# Group 1: configuration hardening
# ---------------------------------------------------------------------------
SSHD_EFFECTIVE=""
load_sshd() {
    if have_cmd sshd && (( EUID == 0 )); then
        SSHD_EFFECTIVE="$(sshd -T 2>/dev/null || true)"
    fi
}
sshd_val() {
    local key="$1" v=""
    if [[ -n "$SSHD_EFFECTIVE" ]]; then
        v="$(printf '%s\n' "$SSHD_EFFECTIVE" | awk -v k="$key" 'tolower($1)==tolower(k){print $2; exit}')"
    fi
    if [[ -z "$v" && -r /etc/ssh/sshd_config ]]; then
        v="$(grep -iE "^[[:space:]]*${key}[[:space:]]+" /etc/ssh/sshd_config 2>/dev/null | tail -n1 | awk '{print $2}')"
    fi
    printf '%s' "$v"
}

check_ssh() {
    [[ -r /etc/ssh/sshd_config || -n "$SSHD_EFFECTIVE" ]] || { add_finding INFO SSH "sshd not configured/installed" ""; return; }
    local v
    v="$(sshd_val permitrootlogin)"
    case "${v,,}" in
        no|prohibit-password) add_finding PASS SSH "PermitRootLogin is '${v}'" "" ;;
        ""|yes)               add_finding HIGH SSH "PermitRootLogin should be 'no' or 'prohibit-password'" "found '${v:-unset}'" ;;
        *)                    add_finding MEDIUM SSH "PermitRootLogin='${v}' - review" "" ;;
    esac
    v="$(sshd_val permitemptypasswords)"
    if [[ "${v,,}" == yes ]]; then add_finding HIGH SSH "PermitEmptyPasswords is enabled" ""; else add_finding PASS SSH "PermitEmptyPasswords disabled" ""; fi
    v="$(sshd_val passwordauthentication)"
    if [[ "${v,,}" == yes ]]; then add_finding LOW SSH "PasswordAuthentication enabled (prefer keys)" ""; else add_finding PASS SSH "PasswordAuthentication restricted" ""; fi
    v="$(sshd_val maxauthtries)"
    if [[ "$v" =~ ^[0-9]+$ ]] && (( v > 4 )); then add_finding LOW SSH "MaxAuthTries high (${v}); recommend <=4" ""; fi
    v="$(sshd_val x11forwarding)"
    [[ "${v,,}" == yes ]] && add_finding LOW SSH "X11Forwarding enabled" ""
}

check_sysctl() {
    local -A want=(
        [net.ipv4.conf.all.accept_redirects]=0
        [net.ipv4.conf.all.send_redirects]=0
        [net.ipv4.conf.all.accept_source_route]=0
        [net.ipv4.tcp_syncookies]=1
        [net.ipv4.conf.all.rp_filter]=1
        [kernel.randomize_va_space]=2
    )
    local k got
    for k in "${!want[@]}"; do
        got="$(sysctl_val "$k")"
        [[ -z "$got" ]] && { add_finding INFO KERNEL "sysctl ${k} unavailable" ""; continue; }
        if [[ "$got" == "${want[$k]}" ]]; then
            add_finding PASS KERNEL "${k}=${got}" ""
        else
            add_finding MEDIUM KERNEL "${k}=${got}, recommended ${want[$k]}" ""
        fi
    done
    local fwd; fwd="$(sysctl_val net.ipv4.ip_forward)"
    [[ "$fwd" == 1 ]] && add_finding INFO KERNEL "net.ipv4.ip_forward=1 (host routes/forwards traffic)" ""
}

check_firewall() {
    local active=0
    if have_cmd ufw && ufw status 2>/dev/null | grep -qi 'Status: active'; then
        add_finding PASS FIREWALL "ufw is active" ""; active=1
    fi
    if have_cmd firewall-cmd && [[ "$(firewall-cmd --state 2>/dev/null)" == running ]]; then
        add_finding PASS FIREWALL "firewalld is running" ""; active=1
    fi
    if (( active == 0 )) && have_cmd nft && [[ -n "$(nft list ruleset 2>/dev/null)" ]]; then
        add_finding PASS FIREWALL "nftables ruleset present" ""; active=1
    fi
    if (( active == 0 )) && have_cmd iptables; then
        local n; n="$(iptables -S 2>/dev/null | grep -cvE '^-P (INPUT|FORWARD|OUTPUT) ACCEPT$|^-N ' || true)"
        if [[ "$n" =~ ^[0-9]+$ ]] && (( n > 0 )); then add_finding PASS FIREWALL "iptables rules present (${n})" ""; active=1; fi
    fi
    (( active == 0 )) && add_finding HIGH FIREWALL "No active host firewall detected" ""
    return 0
}

check_auditd() {
    if have_cmd systemctl; then
        if systemctl is-active auditd >/dev/null 2>&1; then add_finding PASS AUDIT "auditd is active" ""; else add_finding LOW AUDIT "auditd not active" ""; fi
    elif have_cmd service; then
        if service auditd status >/dev/null 2>&1; then add_finding PASS AUDIT "auditd running" ""; else add_finding LOW AUDIT "auditd not detected" ""; fi
    else
        add_finding INFO AUDIT "cannot determine auditd state" ""
    fi
}

check_file_perms() {
    local f mode
    for f in /etc/shadow /etc/gshadow; do
        [[ -e "$f" ]] || continue
        mode="$(stat -c '%a' "$f" 2>/dev/null || true)"
        if [[ -n "$mode" && "$mode" =~ ^(0|00|000|400|600|640)$ ]]; then
            add_finding PASS PERMS "${f} mode ${mode}" ""
        else
            add_finding HIGH PERMS "${f} is over-permissive (mode ${mode:-unknown})" ""
        fi
    done
    if [[ -e /etc/passwd ]]; then
        mode="$(stat -c '%a' /etc/passwd 2>/dev/null || true)"
        if [[ "$mode" =~ ^(644|664|0644)$ ]]; then add_finding PASS PERMS "/etc/passwd mode ${mode}" ""; else add_finding LOW PERMS "/etc/passwd unexpected mode ${mode:-unknown}" ""; fi
    fi

    # World-writable files and unowned files (scoped unless --deep).
    local roots=(/etc /usr/local /var/www /opt)
    (( DEEP )) && roots=(/)
    local ww uno
    ww="$(find "${roots[@]}" -xdev -type f -perm -0002 ! -path '/proc/*' 2>/dev/null | head -n 50 || true)"
    if [[ -n "$ww" ]]; then
        add_finding MEDIUM PERMS "World-writable files found ($(printf '%s\n' "$ww" | grep -c . ))" "$(printf '%s' "$ww" | head -n1)…"
    else
        add_finding PASS PERMS "No world-writable files in scanned paths" ""
    fi
    uno="$(find "${roots[@]}" -xdev \( -nouser -o -nogroup \) 2>/dev/null | head -n 50 || true)"
    [[ -n "$uno" ]] && add_finding LOW PERMS "Unowned files found ($(printf '%s\n' "$uno" | grep -c .))" ""

    # SUID/SGID inventory (informational baseline).
    local suid
    suid="$(find "${roots[@]}" -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | wc -l | tr -d ' ')"
    [[ "$suid" =~ ^[0-9]+$ ]] && add_finding INFO PERMS "SUID/SGID files in scanned paths: ${suid}" ""
}

check_pwpolicy() {
    [[ -r /etc/login.defs ]] || { add_finding INFO PWPOLICY "/etc/login.defs not readable" ""; return; }
    local maxd umask
    maxd="$(awk '/^PASS_MAX_DAYS/{print $2; exit}' /etc/login.defs 2>/dev/null || true)"
    if [[ "$maxd" =~ ^[0-9]+$ ]]; then
        if (( maxd > 365 )); then add_finding LOW PWPOLICY "PASS_MAX_DAYS=${maxd} (>365)" ""; else add_finding PASS PWPOLICY "PASS_MAX_DAYS=${maxd}" ""; fi
    fi
    umask="$(awk '/^UMASK/{print $2; exit}' /etc/login.defs 2>/dev/null || true)"
    [[ -n "$umask" && "$umask" != 027 && "$umask" != 077 ]] && add_finding LOW PWPOLICY "Login UMASK=${umask} (recommend 027)" ""
    if [[ -n "$(find /etc/pam.d -maxdepth 1 -type f 2>/dev/null)" ]] && ! grep -rqiE 'pam_(pwquality|cracklib)\.so' /etc/pam.d/ 2>/dev/null; then
        add_finding LOW PWPOLICY "No pam_pwquality/cracklib password-strength module found" ""
    fi
}

run_hardening() {
    log INFO "== Configuration hardening =="
    load_sshd
    check_ssh; check_sysctl; check_firewall; check_auditd; check_file_perms; check_pwpolicy
}

# ---------------------------------------------------------------------------
# Group 2: accounts & auth
# ---------------------------------------------------------------------------
run_accounts() {
    log INFO "== Accounts & authentication =="
    [[ -r /etc/passwd ]] || { add_finding INFO ACCOUNTS "/etc/passwd not readable" ""; return; }

    local uid0
    uid0="$(awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd 2>/dev/null || true)"
    if [[ -n "$uid0" ]]; then add_finding HIGH ACCOUNTS "Non-root UID 0 account(s): $(printf '%s' "$uid0" | tr '\n' ' ')" ""; else add_finding PASS ACCOUNTS "root is the only UID 0 account" ""; fi

    local dupuid
    dupuid="$(awk -F: '{print $3}' /etc/passwd 2>/dev/null | sort | uniq -d | tr '\n' ' ' || true)"
    [[ -n "${dupuid// /}" ]] && add_finding MEDIUM ACCOUNTS "Duplicate UID(s): ${dupuid}" ""

    if [[ -r /etc/shadow ]]; then
        local empty
        empty="$(awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null || true)"
        if [[ -n "$empty" ]]; then add_finding HIGH ACCOUNTS "Account(s) with empty password: $(printf '%s' "$empty" | tr '\n' ' ')" ""; else add_finding PASS ACCOUNTS "No empty-password accounts" ""; fi
    else
        add_finding INFO ACCOUNTS "/etc/shadow not readable (run as root for empty-password check)" ""
    fi

    # NOPASSWD sudo entries.
    local nopw=""
    if [[ -r /etc/sudoers ]]; then
        nopw="$(grep -rhE 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -vE '^[[:space:]]*#' || true)"
    fi
    [[ -n "$nopw" ]] && add_finding MEDIUM ACCOUNTS "Passwordless sudo (NOPASSWD) entries present" "$(printf '%s' "$nopw" | head -n1)"

    # Accounts with a login shell.
    local shells
    shells="$(awk -F: '($7 ~ /(bash|sh|zsh|ksh|fish)$/){print $1}' /etc/passwd 2>/dev/null | wc -l | tr -d ' ' || true)"
    [[ "$shells" =~ ^[0-9]+$ ]] && add_finding INFO ACCOUNTS "Accounts with interactive shell: ${shells}" ""

    # root-owned world-writable home dirs.
    local wwhome
    wwhome="$(awk -F: '$3>=1000 && $6 ~ /^\/home\//{print $6}' /etc/passwd 2>/dev/null | while read -r h; do
        [[ -d "$h" ]] && [[ "$(stat -c '%a' "$h" 2>/dev/null)" =~ [2367]$ ]] && printf '%s\n' "$h"; done || true)"
    [[ -n "$wwhome" ]] && add_finding LOW ACCOUNTS "Group/world-writable home dir(s): $(printf '%s' "$wwhome" | tr '\n' ' ')" ""
}

# ---------------------------------------------------------------------------
# Group 3: network exposure
# ---------------------------------------------------------------------------
run_network() {
    log INFO "== Network exposure =="
    local listeners=""
    if have_cmd ss; then
        listeners="$(ss -H -tulnp 2>/dev/null || ss -tuln 2>/dev/null || true)"
    elif have_cmd netstat; then
        listeners="$(netstat -tulnp 2>/dev/null | tail -n +3 || true)"
    else
        add_finding INFO NETWORK "Neither ss nor netstat available" ""; return
    fi
    [[ -z "$listeners" ]] && { add_finding PASS NETWORK "No listening sockets detected" ""; return; }

    local total public
    total="$(printf '%s\n' "$listeners" | grep -c . || true)"
    public="$(printf '%s\n' "$listeners" | grep -cE '(\*|0\.0\.0\.0|\[::\]|:::):[0-9]+|0\.0\.0\.0:[0-9]+' || true)"
    add_finding INFO NETWORK "Listening sockets: ${total} (publicly bound: ${public})" ""

    # Enumerate publicly-bound ports.
    local pubports
    pubports="$(printf '%s\n' "$listeners" | grep -oE '(0\.0\.0\.0|\*|\[::\]|:::):[0-9]+' 2>/dev/null | grep -oE '[0-9]+$' | sort -un | tr '\n' ' ' || true)"
    [[ -n "${pubports// /}" ]] && add_finding INFO NETWORK "Public ports: ${pubports}" ""

    # Public listeners with no firewall is a real exposure.
    if [[ "$public" =~ ^[0-9]+$ ]] && (( public > 0 )); then
        local fw=0
        { have_cmd ufw && ufw status 2>/dev/null | grep -qi 'active'; } && fw=1
        { have_cmd firewall-cmd && [[ "$(firewall-cmd --state 2>/dev/null)" == running ]]; } && fw=1
        { have_cmd nft && [[ -n "$(nft list ruleset 2>/dev/null)" ]]; } && fw=1
        (( fw == 0 )) && add_finding MEDIUM NETWORK "Publicly-bound services with no active firewall" ""
    fi
}

# ---------------------------------------------------------------------------
# Group 4: vulnerability / CVE
# ---------------------------------------------------------------------------
run_vuln() {
    log INFO "== Vulnerability / CVE =="
    if is_debian_like && have_cmd apt-get; then
        local up sec
        up="$(apt-get -s -o Debug::NoLocking=true upgrade 2>/dev/null | grep -c '^Inst ' || true)"
        sec="$( { apt-get -s -o Debug::NoLocking=true upgrade 2>/dev/null | grep '^Inst ' | grep -ci security; } || true)"
        [[ "$up" =~ ^[0-9]+$ ]] || up=0
        [[ "$sec" =~ ^[0-9]+$ ]] || sec=0
        if (( sec > 0 )); then add_finding HIGH VULN "${sec} pending security update(s) (${up} total upgradable)" ""
        elif (( up > 0 )); then add_finding LOW VULN "${up} package update(s) available (no security-flagged)" ""
        else add_finding PASS VULN "No pending package updates" ""; fi
    elif is_rhel_like && have_cmd dnf; then
        local sec
        sec="$(dnf -q updateinfo list security 2>/dev/null | grep -cE '/Sec\.|Security' || true)"
        [[ "$sec" =~ ^[0-9]+$ ]] || sec=0
        if (( sec > 0 )); then add_finding HIGH VULN "${sec} security advisory update(s) available" ""; else add_finding PASS VULN "No pending security advisories" ""; fi
    elif have_cmd yum; then
        local sec; sec="$(yum -q updateinfo list security 2>/dev/null | grep -c . || true)"
        if [[ "$sec" =~ ^[0-9]+$ ]] && (( sec > 0 )); then add_finding HIGH VULN "${sec} security update line(s) reported by yum" ""; else add_finding INFO VULN "yum security updateinfo returned nothing" ""; fi
    else
        add_finding INFO VULN "No supported package manager for update check" ""
    fi

    # Hybrid: container/filesystem vuln scanners when present (heavy -> --deep only).
    if (( USE_EXTERNAL )); then
        if have_cmd trivy && (( DEEP )); then
            local out; out="$(timeout 600s trivy rootfs --quiet --scanners vuln --severity HIGH,CRITICAL / 2>/dev/null || true)"
            local hc; hc="$(printf '%s\n' "$out" | grep -cE 'CRITICAL|HIGH' || true)"
            if [[ "$hc" =~ ^[0-9]+$ ]] && (( hc > 0 )); then add_finding HIGH VULN "Trivy reported ${hc} HIGH/CRITICAL finding line(s)" ""; else add_finding PASS VULN "Trivy found no HIGH/CRITICAL (rootfs)" ""; fi
        elif have_cmd trivy; then
            add_finding INFO VULN "trivy present; re-run with --deep for a full rootfs scan" ""
        fi
        if have_cmd grype && ! have_cmd trivy && (( DEEP )); then
            add_finding INFO VULN "grype present; full scan via grype dir:/ (run manually for depth)" ""
        fi
    fi
}

# ---------------------------------------------------------------------------
# Group 5: rootkit & file integrity
# ---------------------------------------------------------------------------
run_rootkit() {
    log INFO "== Rootkit & file integrity =="

    # Native indicators (cheap, no deps).
    local promisc
    if have_cmd ip; then
        promisc="$(ip -o link show 2>/dev/null | grep -i PROMISC | awk -F': ' '{print $2}' | awk '{print $1}' | tr '\n' ' ' || true)"
        [[ -n "${promisc// /}" ]] && add_finding MEDIUM ROOTKIT "Interface(s) in promiscuous mode: ${promisc}" ""
    fi
    local deleted
    deleted="$( { for e in /proc/[0-9]*/exe; do readlink "$e" 2>/dev/null || true; done; } | grep -c '(deleted)' || true)"
    [[ "$deleted" =~ ^[0-9]+$ ]] && (( deleted > 0 )) && add_finding LOW ROOTKIT "${deleted} running process(es) with a deleted executable" ""

    # Hybrid: dedicated tools when present.
    if (( USE_EXTERNAL )); then
        if have_cmd rkhunter && (( DEEP )); then
            local warn; warn="$(timeout 600s rkhunter --check --sk --nocolors --rwo 2>/dev/null | grep -c . || true)"
            if [[ "$warn" =~ ^[0-9]+$ ]] && (( warn > 0 )); then add_finding MEDIUM ROOTKIT "rkhunter reported ${warn} warning line(s)" ""; else add_finding PASS ROOTKIT "rkhunter: no warnings" ""; fi
        elif have_cmd rkhunter; then
            add_finding INFO ROOTKIT "rkhunter present; re-run with --deep to execute it" ""
        fi
        if have_cmd chkrootkit && (( DEEP )); then
            local inf; inf="$(timeout 300s chkrootkit 2>/dev/null | grep -c 'INFECTED' || true)"
            if [[ "$inf" =~ ^[0-9]+$ ]] && (( inf > 0 )); then add_finding HIGH ROOTKIT "chkrootkit reported ${inf} INFECTED result(s)" ""; else add_finding PASS ROOTKIT "chkrootkit: nothing infected" ""; fi
        fi
    fi
}

run_integrity() {
    log INFO "== File integrity baseline =="
    if have_cmd aide; then
        local db=""
        for d in /var/lib/aide/aide.db.gz /var/lib/aide/aide.db /etc/aide/aide.db.gz; do
            [[ -e "$d" ]] && { db="$d"; break; }
        done
        if [[ -z "$db" ]]; then
            add_finding LOW INTEGRITY "AIDE installed but no database initialized" "run: aide --init"
        elif (( DEEP )); then
            local changed; changed="$(timeout 900s aide --check 2>/dev/null | grep -cE 'changed|added|removed' || true)"
            if [[ "$changed" =~ ^[0-9]+$ ]] && (( changed > 0 )); then add_finding MEDIUM INTEGRITY "AIDE reports ${changed} change line(s) vs baseline" ""; else add_finding PASS INTEGRITY "AIDE: no changes vs baseline" ""; fi
        else
            add_finding INFO INTEGRITY "AIDE database present; re-run with --deep for aide --check" ""
        fi
    else
        add_finding LOW INTEGRITY "No file-integrity tool (AIDE) installed" ""
    fi

    # Hybrid: reuse the SCAP companion if available and oscap is installed.
    if (( USE_EXTERNAL )) && [[ -x "${SCRIPT_DIR}/SCAP-Scan.sh" ]] && have_cmd oscap; then
        add_finding INFO INTEGRITY "SCAP-Scan.sh + oscap available for benchmark compliance" "run: ${SCRIPT_DIR}/SCAP-Scan.sh --list-profiles"
    fi

    # Hybrid: Lynis hardening audit if present.
    if (( USE_EXTERNAL )) && have_cmd lynis; then
        if (( DEEP )); then
            local hi; hi="$(timeout 600s lynis audit system --quiet --no-colors 2>/dev/null | grep -c 'Warning\|Suggestion' || true)"
            [[ "$hi" =~ ^[0-9]+$ ]] && add_finding INFO INTEGRITY "Lynis produced ${hi} warning/suggestion line(s)" ""
        else
            add_finding INFO INTEGRITY "lynis present; re-run with --deep to run 'lynis audit system'" ""
        fi
    fi
}

# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
write_json() {
    local out="$1" i sev cat title detail IFS='|'
    {
        printf '{\n'
        printf '  "tool": "linux-security-scan.sh",\n'
        printf '  "version": "%s",\n' "$VERSION"
        printf '  "scanTime": "%s",\n' "$(date '+%Y-%m-%dT%H:%M:%S%z')"
        printf '  "host": "%s",\n' "$(json_escape "$(hostname 2>/dev/null || echo unknown)")"
        printf '  "os": "%s",\n' "$(json_escape "$OS_PRETTY")"
        printf '  "privileged": %s,\n' "$( ((EUID==0)) && echo true || echo false )"
        printf '  "summary": { "high": %s, "medium": %s, "low": %s, "info": %s, "pass": %s },\n' \
            "${SEV_COUNT[HIGH]}" "${SEV_COUNT[MEDIUM]}" "${SEV_COUNT[LOW]}" "${SEV_COUNT[INFO]}" "${SEV_COUNT[PASS]}"
        printf '  "findings": [\n'
        for ((i=0; i<${#FINDINGS[@]}; i++)); do
            read -r sev cat title detail <<<"${FINDINGS[$i]}"
            printf '    {"severity":"%s","category":"%s","title":"%s","detail":"%s"}%s\n' \
                "$sev" "$(json_escape "$cat")" "$(json_escape "$title")" "$(json_escape "$detail")" \
                "$( (( i < ${#FINDINGS[@]}-1 )) && echo , )"
        done
        printf '  ]\n}\n'
    } >"$out"
    log SUCCESS "JSON report: $out"
}

write_html() {
    local out="$1" i sev cat title detail IFS='|'
    {
        cat <<HTMLHEAD
<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Linux Security Scan Report</title>
<style>
 body{font-family:system-ui,Segoe UI,Roboto,sans-serif;margin:2rem;color:#1b1f24;background:#fff}
 h1{margin:0 0 .25rem} .meta{color:#555;font-size:.9rem;margin-bottom:1rem}
 .cards{display:flex;gap:.5rem;flex-wrap:wrap;margin:1rem 0}
 .card{padding:.5rem .9rem;border-radius:.5rem;color:#fff;font-weight:600}
 .HIGH{background:#c0392b}.MEDIUM{background:#e67e22}.LOW{background:#2980b9}.INFO{background:#7f8c8d}.PASS{background:#27ae60}
 table{border-collapse:collapse;width:100%;font-size:.92rem}
 th,td{border:1px solid #e1e4e8;padding:.4rem .6rem;text-align:left;vertical-align:top}
 th{background:#f6f8fa} tr:nth-child(even){background:#fbfcfd}
 .badge{display:inline-block;padding:.1rem .5rem;border-radius:.4rem;color:#fff;font-size:.8rem}
</style></head><body>
<h1>Linux Security Scan Report</h1>
HTMLHEAD
        printf '<div class="meta">Host: %s &middot; OS: %s &middot; %s &middot; privileged: %s</div>\n' \
            "$(html_escape "$(hostname 2>/dev/null || echo unknown)")" "$(html_escape "$OS_PRETTY")" \
            "$(date '+%Y-%m-%d %H:%M:%S')" "$( ((EUID==0)) && echo yes || echo no )"
        printf '<div class="cards">'
        local s
        for s in HIGH MEDIUM LOW INFO PASS; do
            printf '<div class="card %s">%s: %s</div>' "$s" "$s" "${SEV_COUNT[$s]}"
        done
        printf '</div>\n<table><thead><tr><th>Severity</th><th>Category</th><th>Finding</th><th>Detail</th></tr></thead><tbody>\n'
        for ((i=0; i<${#FINDINGS[@]}; i++)); do
            read -r sev cat title detail <<<"${FINDINGS[$i]}"
            printf '<tr><td><span class="badge %s">%s</span></td><td>%s</td><td>%s</td><td>%s</td></tr>\n' \
                "$sev" "$sev" "$(html_escape "$cat")" "$(html_escape "$title")" "$(html_escape "$detail")"
        done
        printf '</tbody></table></body></html>\n'
    } >"$out"
    log SUCCESS "HTML report: $out"
}

print_summary() {
    printf '\n%s======== Scan Summary ========%s\n' "$C_CYAN" "$C_RESET" >&2
    printf '  %sHIGH:   %s%s\n' "$C_RED" "${SEV_COUNT[HIGH]}" "$C_RESET" >&2
    printf '  %sMEDIUM: %s%s\n' "$C_YELLOW" "${SEV_COUNT[MEDIUM]}" "$C_RESET" >&2
    printf '  %sLOW:    %s%s\n' "$C_BLUE" "${SEV_COUNT[LOW]}" "$C_RESET" >&2
    printf '  INFO:   %s\n' "${SEV_COUNT[INFO]}" >&2
    printf '  %sPASS:   %s%s\n' "$C_GREEN" "${SEV_COUNT[PASS]}" "$C_RESET" >&2
    printf '%s==============================%s\n' "$C_CYAN" "$C_RESET" >&2
}

# ---------------------------------------------------------------------------
# Usage / args
# ---------------------------------------------------------------------------
usage() {
    cat <<EOF
linux-security-scan.sh v${VERSION} - hybrid Linux security scanner

Usage: sudo $0 [options]

Options:
  -o, --output-dir DIR   Report directory (default: ./SecurityScan_Reports)
  -f, --format FMT       text|json|html|all (default: all)
      --only LIST        Comma list of groups to run (${ALL_GROUPS// /,})
      --skip LIST        Comma list of groups to skip
      --no-external      Native checks only; do not use installed external tools
      --deep             Run slow/heavy scans (full-fs walk, trivy, rkhunter, aide --check, lynis)
  -h, --help             Show this help

Groups: ${ALL_GROUPS// /, }
Run as root for full coverage (shadow, sshd -T, auditd, etc.).
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -o|--output-dir) OUTPUT_DIR="${2:?}"; shift 2 ;;
            -f|--format)     FORMAT="${2:?}"; shift 2 ;;
            --only)          ONLY="${2:?}"; shift 2 ;;
            --skip)          SKIP="${2:?}"; shift 2 ;;
            --no-external)   USE_EXTERNAL=0; shift ;;
            --deep)          DEEP=1; shift ;;
            -h|--help)       usage; exit 0 ;;
            *)               usage; die "Unknown option: $1" ;;
        esac
    done
    case "$FORMAT" in text|json|html|all) ;; *) die "Invalid --format '$FORMAT'";; esac
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    parse_args "$@"
    read_os

    mkdir -p "$OUTPUT_DIR" || die "Cannot create output dir: $OUTPUT_DIR"
    local stamp; stamp="$(date '+%Y%m%d_%H%M%S')"
    LOG_FILE="${OUTPUT_DIR}/security_scan_${stamp}.log"

    printf '\n%s=============================%s\n' "$C_CYAN" "$C_RESET" >&2
    printf '%s Linux Security Scan v%s %s\n' "$C_CYAN" "$VERSION" "$C_RESET" >&2
    printf '%s=============================%s\n' "$C_CYAN" "$C_RESET" >&2
    log INFO "Host: $(hostname 2>/dev/null || echo unknown) | OS: ${OS_PRETTY:-unknown} | privileged: $( ((EUID==0)) && echo yes || echo no) | deep: ${DEEP} | external: ${USE_EXTERNAL}"
    (( EUID == 0 )) || log INFO "Not running as root; some checks will be limited."

    group_enabled hardening && run_hardening
    group_enabled accounts  && run_accounts
    group_enabled network   && run_network
    group_enabled vuln      && run_vuln
    group_enabled rootkit   && run_rootkit
    group_enabled integrity && run_integrity

    print_summary

    local base="${OUTPUT_DIR}/security_scan_${stamp}"
    [[ "$FORMAT" == json || "$FORMAT" == all ]] && write_json "${base}.json"
    [[ "$FORMAT" == html || "$FORMAT" == all ]] && write_html "${base}.html"
    log SUCCESS "Text log: $LOG_FILE"

    # Exit non-zero when HIGH findings exist, so CI/cron can gate on it.
    (( SEV_COUNT[HIGH] > 0 )) && return 2
    return 0
}

main "$@"
