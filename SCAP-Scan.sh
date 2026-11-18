#!/usr/bin/env bash
#
# SCAP-Scan.sh - Linux SCAP compliance scanner (OpenSCAP companion to SCAP-Scanner.ps1)
#
# Runs OpenSCAP (oscap) compliance scans on the local Debian/Ubuntu or
# Fedora/RHEL-family host using SCAP Security Guide (SSG) content, and produces
# XML/HTML/ARF reports plus an optional JSON summary.
#
# OpenSCAP is the Linux counterpart to SCC on Windows. (OpenSCAP removed
# Microsoft Windows support on 2022-02-01; use SCAP-Scanner.ps1 with SCC for
# Windows hosts.) Unlike Windows SCAP content, SSG content is open and ships in
# the distro packages, so this script can install and locate it automatically.
#
# Local scanning only: a non-local target is rejected rather than mislabeled,
# matching SCAP-Scanner.ps1.

set -euo pipefail

readonly SCRIPT_VERSION="1.0.0"
readonly SSG_CONTENT_DIR="/usr/share/xml/scap/ssg/content"

# ---------------------------------------------------------------------------
# Defaults (override via options)
# ---------------------------------------------------------------------------
BENCHMARK=""              # friendly keyword: cis, stig, pci-dss, ospp, standard, anssi, hipaa
PROFILE=""                # explicit xccdf profile id (wins over --benchmark)
CONTENT=""                # explicit datastream path (wins over auto-detection)
TARGET="localhost"        # local only
OUTPUT_DIR="./SCAP_Reports"
REPORT_FORMAT="html"      # xml | html | arf | all
TIMEOUT=3600              # seconds
TAILORING=""              # optional tailoring file
EXPORT_DIR=""             # optional JSON summary destination
DO_INSTALL=0
DO_LIST_PROFILES=0
LOG_FILE=""

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
if [[ -t 1 ]]; then
    C_RESET=$'\033[0m'; C_RED=$'\033[31m'; C_GREEN=$'\033[32m'
    C_YELLOW=$'\033[33m'; C_CYAN=$'\033[36m'
else
    C_RESET=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_CYAN=""
fi

log() {
    # log LEVEL MESSAGE
    local level="$1"; shift
    local msg="$*"
    local ts color
    ts="$(date '+%Y-%m-%d %H:%M:%S')"
    case "$level" in
        WARNING) color="$C_YELLOW" ;;
        ERROR)   color="$C_RED" ;;
        SUCCESS) color="$C_GREEN" ;;
        *)       color="" ;;
    esac
    local line="${ts} - [${level}] - ${msg}"
    printf '%s%s%s\n' "$color" "$line" "$C_RESET" >&2
    if [[ -n "$LOG_FILE" ]]; then
        printf '%s\n' "$line" >>"$LOG_FILE" 2>/dev/null || true
    fi
}

die() { log ERROR "$*"; exit 1; }

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------
usage() {
    cat <<EOF
SCAP-Scan.sh v${SCRIPT_VERSION} - OpenSCAP compliance scanner for Linux

Usage: $0 [options]

Options:
  -b, --benchmark KEYWORD   Select a profile whose id contains KEYWORD
                            (cis, stig, pci-dss, ospp, standard, anssi, hipaa).
  -p, --profile ID          Explicit XCCDF profile id (overrides --benchmark).
  -c, --content PATH        Explicit SCAP datastream file (overrides auto-detect).
  -t, --target HOST         Target host (local only; default: localhost).
  -o, --output-dir DIR      Report output directory (default: ./SCAP_Reports).
  -f, --format FORMAT       Report format: xml|html|arf|all (default: html).
      --timeout SECONDS     Scan timeout in seconds (default: 3600).
      --tailoring FILE      Optional XCCDF tailoring file.
      --export DIR          Also write a JSON summary into DIR.
      --install             Install OpenSCAP and SSG content if missing.
      --list-profiles       List profiles in the resolved datastream and exit.
  -h, --help                Show this help.

Examples:
  sudo $0 --install --benchmark cis --format all
  sudo $0 --profile xccdf_org.ssgproject.content_profile_stig
  $0 --list-profiles
EOF
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        -b|--benchmark)   BENCHMARK="${2:?--benchmark needs a value}"; shift 2 ;;
        -p|--profile)     PROFILE="${2:?--profile needs a value}"; shift 2 ;;
        -c|--content)     CONTENT="${2:?--content needs a value}"; shift 2 ;;
        -t|--target)      TARGET="${2:?--target needs a value}"; shift 2 ;;
        -o|--output-dir)  OUTPUT_DIR="${2:?--output-dir needs a value}"; shift 2 ;;
        -f|--format)      REPORT_FORMAT="${2:?--format needs a value}"; shift 2 ;;
        --timeout)        TIMEOUT="${2:?--timeout needs a value}"; shift 2 ;;
        --tailoring)      TAILORING="${2:?--tailoring needs a value}"; shift 2 ;;
        --export)         EXPORT_DIR="${2:?--export needs a value}"; shift 2 ;;
        --install)        DO_INSTALL=1; shift ;;
        --list-profiles)  DO_LIST_PROFILES=1; shift ;;
        -h|--help)        usage; exit 0 ;;
        *)                usage; die "Unknown option: $1" ;;
    esac
done

# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
case "$REPORT_FORMAT" in
    xml|html|arf|all) ;;
    *) die "Invalid --format '$REPORT_FORMAT' (expected xml|html|arf|all)" ;;
esac

if ! [[ "$TIMEOUT" =~ ^[0-9]+$ ]] || (( TIMEOUT < 1 || TIMEOUT > 2147483 )); then
    die "--timeout must be an integer between 1 and 2147483 seconds"
fi

case "$TARGET" in
    localhost|127.0.0.1|::1|.|"$(hostname 2>/dev/null)"|"$(hostname -s 2>/dev/null)")
        ;;
    *)
        die "Remote scanning is not implemented. Run this script on '$TARGET' instead."
        ;;
esac

# ---------------------------------------------------------------------------
# Distro detection -> SSG datastream product
# ---------------------------------------------------------------------------
detect_product() {
    # Echoes the SSG product basename (without ssg- prefix / -ds.xml suffix).
    [[ -r /etc/os-release ]] || die "/etc/os-release not found; cannot detect distribution."
    # shellcheck disable=SC1091
    . /etc/os-release
    local id="${ID:-}" id_like="${ID_LIKE:-}" ver="${VERSION_ID:-}"
    local major="${ver%%.*}"

    case "$id" in
        debian)              echo "debian${major}" ;;
        ubuntu)              echo "ubuntu${ver//./}" ;;
        fedora)              echo "fedora" ;;
        rhel|redhat)         echo "rhel${major}" ;;
        centos)              echo "centos${major}" ;;
        rocky|almalinux|ol|oraclelinux)
                             echo "rhel${major}" ;;
        *)
            # Fall back to the distro family via ID_LIKE.
            if [[ "$id_like" == *debian* ]]; then
                echo "debian${major:-12}"
            elif [[ "$id_like" == *fedora* || "$id_like" == *rhel* ]]; then
                echo "rhel${major:-9}"
            else
                echo ""
            fi
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Installation
# ---------------------------------------------------------------------------
install_scanner() {
    (( EUID == 0 )) || die "--install requires root. Re-run with sudo."
    [[ -r /etc/os-release ]] || die "/etc/os-release not found; cannot detect package manager."
    # shellcheck disable=SC1091
    . /etc/os-release
    local family="${ID:-}${ID_LIKE:+ $ID_LIKE}"

    if command -v apt-get >/dev/null 2>&1; then
        log INFO "Installing OpenSCAP and SSG content via apt-get"
        DEBIAN_FRONTEND=noninteractive apt-get update
        # ssg package names vary by release; install what resolves, keep going.
        DEBIAN_FRONTEND=noninteractive apt-get install -y openscap-scanner || \
            die "Failed to install openscap-scanner via apt-get"
        local pkg
        for pkg in ssg-base ssg-debian ssg-debderived ssg-applications; do
            if DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" 2>/dev/null; then
                log INFO "Installed $pkg"
            else
                log WARNING "Package $pkg not available; skipping"
            fi
        done
    elif command -v dnf >/dev/null 2>&1; then
        log INFO "Installing OpenSCAP and SSG content via dnf"
        dnf install -y openscap-scanner scap-security-guide \
            || die "Failed to install openscap-scanner / scap-security-guide via dnf"
    elif command -v yum >/dev/null 2>&1; then
        log INFO "Installing OpenSCAP and SSG content via yum"
        yum install -y openscap-scanner scap-security-guide \
            || die "Failed to install openscap-scanner / scap-security-guide via yum"
    else
        die "No supported package manager (apt-get/dnf/yum) found for '$family'."
    fi
    log SUCCESS "Installation step completed"
}

# ---------------------------------------------------------------------------
# Datastream resolution
# ---------------------------------------------------------------------------
resolve_datastream() {
    # Echoes an existing datastream path or exits.
    if [[ -n "$CONTENT" ]]; then
        [[ -f "$CONTENT" ]] || die "Specified --content not found: $CONTENT"
        echo "$CONTENT"; return
    fi

    local product
    product="$(detect_product)"
    [[ -n "$product" ]] || die "Could not map this distribution to an SSG product. Pass --content explicitly."

    local candidates=(
        "${SSG_CONTENT_DIR}/ssg-${product}-ds.xml"
    )
    # Version fallbacks: ssg may lag the running release.
    case "$product" in
        debian*) candidates+=("${SSG_CONTENT_DIR}/ssg-debian12-ds.xml" "${SSG_CONTENT_DIR}/ssg-debian11-ds.xml") ;;
        ubuntu*) candidates+=("${SSG_CONTENT_DIR}/ssg-ubuntu2404-ds.xml" "${SSG_CONTENT_DIR}/ssg-ubuntu2204-ds.xml") ;;
        rhel*|centos*) candidates+=("${SSG_CONTENT_DIR}/ssg-rhel9-ds.xml" "${SSG_CONTENT_DIR}/ssg-rhel8-ds.xml") ;;
    esac

    local c
    for c in "${candidates[@]}"; do
        if [[ -f "$c" ]]; then
            log SUCCESS "Using SCAP content: $c"
            echo "$c"; return
        fi
    done

    # Last resort: first datastream present on the system.
    if [[ -d "$SSG_CONTENT_DIR" ]]; then
        local first
        first="$(find "$SSG_CONTENT_DIR" -maxdepth 1 -name 'ssg-*-ds.xml' -print -quit 2>/dev/null || true)"
        if [[ -n "$first" ]]; then
            log WARNING "No exact match for '$product'; falling back to $first"
            echo "$first"; return
        fi
    fi

    die "No SSG datastream found under ${SSG_CONTENT_DIR}. Run with --install, or pass --content."
}

list_profiles() {
    local ds="$1"
    command -v oscap >/dev/null 2>&1 || die "oscap not found. Run with --install."
    log INFO "Profiles available in $ds:"
    oscap info --profiles "$ds" 2>/dev/null || oscap info "$ds"
}

resolve_profile() {
    # Echoes a profile id, using --profile, else --benchmark keyword match.
    local ds="$1"
    if [[ -n "$PROFILE" ]]; then
        echo "$PROFILE"; return
    fi
    [[ -n "$BENCHMARK" ]] || die "No profile selected. Pass --profile ID or --benchmark KEYWORD (see --list-profiles)."

    local ids
    ids="$(oscap info --profiles "$ds" 2>/dev/null | cut -d: -f1 || true)"
    [[ -n "$ids" ]] || die "Could not read profiles from $ds. Try --list-profiles."

    local match
    match="$(printf '%s\n' "$ids" | grep -i -- "$BENCHMARK" | head -n1 || true)"
    [[ -n "$match" ]] || die "No profile in $ds matches '$BENCHMARK'. See --list-profiles."

    local count
    count="$(printf '%s\n' "$ids" | grep -ic -- "$BENCHMARK" || true)"
    (( count > 1 )) && log WARNING "Multiple profiles match '$BENCHMARK'; using first: $match"
    echo "$match"
}

# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------
run_scan() {
    # run_scan DATASTREAM PROFILE  -> sets globals RESULT_XML / REPORT_HTML / ARF_XML (those produced)
    local ds="$1" profile="$2"
    command -v oscap >/dev/null 2>&1 || die "oscap not found. Run with --install."

    mkdir -p "$OUTPUT_DIR"
    local stamp base
    stamp="$(date '+%Y%m%d_%H%M%S')"
    base="${OUTPUT_DIR}/SCAP_Scan_${TARGET}_${stamp}"

    RESULT_XML="${base}.results.xml"
    REPORT_HTML="${base}.report.html"
    ARF_XML="${base}.arf.xml"

    local args=(xccdf eval --profile "$profile" --results "$RESULT_XML")
    [[ "$REPORT_FORMAT" == "html" || "$REPORT_FORMAT" == "all" ]] && args+=(--report "$REPORT_HTML")
    [[ "$REPORT_FORMAT" == "arf"  || "$REPORT_FORMAT" == "all" ]] && args+=(--results-arf "$ARF_XML")
    [[ -n "$TAILORING" ]] && { [[ -f "$TAILORING" ]] || die "Tailoring file not found: $TAILORING"; args+=(--tailoring-file "$TAILORING"); }
    args+=("$ds")

    log INFO "Running: oscap ${args[*]}"
    local rc=0
    if command -v timeout >/dev/null 2>&1; then
        timeout --signal=TERM "${TIMEOUT}s" oscap "${args[@]}" || rc=$?
    else
        oscap "${args[@]}" || rc=$?
    fi

    # oscap: 0 = all rules pass, 2 = evaluation completed with failures/unknowns,
    # 1 = error. timeout(1): 124 = killed on timeout.
    case "$rc" in
        0|2) : ;;
        124) die "Scan timed out after ${TIMEOUT}s" ;;
        *)   die "oscap evaluation failed (exit $rc)" ;;
    esac

    [[ -s "$RESULT_XML" ]] || die "Scan produced no results file: $RESULT_XML"

    # Enforce that requested HTML/ARF artifacts were actually created.
    if [[ "$REPORT_FORMAT" == "html" || "$REPORT_FORMAT" == "all" ]]; then
        [[ -s "$REPORT_HTML" ]] || die "Requested HTML report was not produced: $REPORT_HTML"
    fi
    if [[ "$REPORT_FORMAT" == "arf" || "$REPORT_FORMAT" == "all" ]]; then
        [[ -s "$ARF_XML" ]] || die "Requested ARF report was not produced: $ARF_XML"
    fi

    # On-demand XML->HTML when only XML was requested but the caller later wants it:
    # handled by format selection above; nothing extra needed here.
    log SUCCESS "Scan completed ($( [[ $rc -eq 0 ]] && echo 'all rules passed' || echo 'findings present' ))"
}

# ---------------------------------------------------------------------------
# Summary / counts
# ---------------------------------------------------------------------------
count_result() {
    # count_result RESULTS_XML RESULT_TYPE
    # Always prints a non-negative integer and exits 0, so a zero count
    # (grep exit 1) cannot abort the caller under 'set -e'/pipefail.
    local file="$1" type="$2" n=0
    if command -v xmllint >/dev/null 2>&1; then
        n="$(xmllint --xpath "count(//*[local-name()='rule-result']/*[local-name()='result'][.='${type}'])" "$file" 2>/dev/null)" || n=0
    else
        # Fallback: count <result>TYPE</result> occurrences in the results file.
        n="$( { grep -o "<result>${type}</result>" "$file" 2>/dev/null || true; } | wc -l | tr -d ' ')"
    fi
    [[ "$n" =~ ^[0-9]+$ ]] || n=0
    printf '%s' "$n"
}

print_summary() {
    local results="$1" profile="$2" ds="$3"
    local pass fail error unknown notapplicable
    pass="$(count_result "$results" pass)"
    fail="$(count_result "$results" fail)"
    error="$(count_result "$results" error)"
    unknown="$(count_result "$results" unknown)"
    notapplicable="$(count_result "$results" notapplicable)"

    local scored=$(( pass + fail ))
    local score="n/a"
    if (( scored > 0 )); then
        score="$(awk -v p="$pass" -v s="$scored" 'BEGIN{ printf "%.1f", (p/s)*100 }')"
    fi

    printf '\n%s=============================%s\n' "$C_CYAN" "$C_RESET" >&2
    printf '%s SCAP Scan Summary %s\n' "$C_CYAN" "$C_RESET" >&2
    printf '%s=============================%s\n' "$C_CYAN" "$C_RESET" >&2
    printf 'Target:    %s\n' "$TARGET" >&2
    printf 'Profile:   %s\n' "$profile" >&2
    printf 'Content:   %s\n' "$ds" >&2
    printf '%sPass: %s%s   %sFail: %s%s   Error: %s   Unknown: %s   N/A: %s\n' \
        "$C_GREEN" "$pass" "$C_RESET" "$C_RED" "$fail" "$C_RESET" "$error" "$unknown" "$notapplicable" >&2
    printf 'Compliance (pass / (pass+fail)): %s%%\n' "$score" >&2
    printf 'Log file:  %s\n' "${LOG_FILE:-<none>}" >&2
    printf '%s=============================%s\n\n' "$C_CYAN" "$C_RESET" >&2

    SUMMARY_PASS="$pass"; SUMMARY_FAIL="$fail"; SUMMARY_ERROR="$error"
    SUMMARY_UNKNOWN="$unknown"; SUMMARY_NA="$notapplicable"; SUMMARY_SCORE="$score"
}

export_json() {
    local dir="$1" results="$2" profile="$3" ds="$4"
    mkdir -p "$dir"
    local out
    out="${dir}/SCAP_Export_$(date '+%Y%m%d_%H%M%S').json"
    local produced=()
    [[ -s "$RESULT_XML" ]]  && produced+=("\"$RESULT_XML\"")
    [[ -s "${REPORT_HTML:-}" ]] && produced+=("\"$REPORT_HTML\"")
    [[ -s "${ARF_XML:-}" ]]     && produced+=("\"$ARF_XML\"")
    local files_csv
    files_csv="$(IFS=,; echo "${produced[*]:-}")"

    cat >"$out" <<EOF
{
  "scanTime": "$(date '+%Y-%m-%dT%H:%M:%S%z')",
  "scanner": "OpenSCAP",
  "target": "${TARGET}",
  "content": "${ds}",
  "profile": "${profile}",
  "results": {
    "pass": ${SUMMARY_PASS:-0},
    "fail": ${SUMMARY_FAIL:-0},
    "error": ${SUMMARY_ERROR:-0},
    "unknown": ${SUMMARY_UNKNOWN:-0},
    "notApplicable": ${SUMMARY_NA:-0},
    "complianceScore": "${SUMMARY_SCORE:-n/a}"
  },
  "outputFiles": [${files_csv}]
}
EOF
    log SUCCESS "Exported JSON summary to $out"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    printf '\n%s=============================%s\n' "$C_CYAN" "$C_RESET" >&2
    printf '%s SCAP Scanner (Linux/OpenSCAP) v%s %s\n' "$C_CYAN" "$SCRIPT_VERSION" "$C_RESET" >&2
    printf '%s=============================%s\n\n' "$C_CYAN" "$C_RESET" >&2

    mkdir -p "$OUTPUT_DIR"
    LOG_FILE="${OUTPUT_DIR}/SCAP_Scan_$(date '+%Y%m%d_%H%M%S').log"

    (( DO_INSTALL )) && install_scanner

    local datastream
    datastream="$(resolve_datastream)"

    if (( DO_LIST_PROFILES )); then
        list_profiles "$datastream"
        exit 0
    fi

    # Scanning the local host benefits from root (many checks read protected files).
    (( EUID == 0 )) || log WARNING "Not running as root; some checks may report 'notchecked' or 'error'."

    local profile
    profile="$(resolve_profile "$datastream")"
    log INFO "Selected profile: $profile"

    run_scan "$datastream" "$profile"
    print_summary "$RESULT_XML" "$profile" "$datastream"

    [[ -n "$EXPORT_DIR" ]] && export_json "$EXPORT_DIR" "$RESULT_XML" "$profile" "$datastream"

    log SUCCESS "Done. Reports in: $OUTPUT_DIR"
}

main "$@"
