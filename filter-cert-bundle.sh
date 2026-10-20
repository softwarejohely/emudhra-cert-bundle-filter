#!/bin/zsh -f
#
# Remove the blocked eMudhra/AAA roots from macOS's /etc/ssl/cert.pem.
#
# macOS blocks the compromised intermediates in its system trust store, but
# /usr/bin/curl reads /etc/ssl/cert.pem, does not check revocation, and Apple has
# not updated that file. This removes the certificates whose public keys
# (SPKI sha256) match the three that Homebrew's ca-certificates formula
# excludes, keeping the rest of the file (including Apple's header comments).
#
# Run as root, once by hand or daily from an MDM script. A macOS update restores Apple's file, so
# it re-applies the filter; once Apple ships a fixed file it finds nothing to do.
#
# Safe by construction: the new file is built beside the original, checked, and
# only then swapped in with an atomic rename. One backup is kept the first time.
# Exits 0 if nothing needed removing or the filter was applied and verified;
# exits 1 on any problem, leaving the original file untouched.

# Test hook: only a non-root run may point BUNDLE somewhere else. As root (MDM) the
# target is always the system file, whatever the environment says.
if (( EUID == 0 )); then
    BUNDLE=/etc/ssl/cert.pem
else
    BUNDLE="${BUNDLE:-/etc/ssl/cert.pem}"
fi
BACKUP="${BUNDLE}.pre-emudhra-filter"

# From Homebrew's ca-certificates formula (EXCLUDED_SPKI_HASHES)
typeset -a BLOCKED_SPKI=(
    bd153ed7b0434f6886b17bce8bbe84ed340c7132d702a8f4fa318f756ecbd6f3
    c619e4780ed8e0abeda24ad732567de4383a7ea941338f6d1a7d1b49ac792fe9
    8d417db2dd8bf5e3084d1e3f196d583849d81bdd4c00c70b9d39369e96b8c782
)

log() { echo "$(/bin/date '+%Y-%m-%d %H:%M:%S') $*"; }

# Split a PEM bundle into one file per certificate (1.pem, 2.pem, ...) in $2.
# Fails on nested BEGIN markers, an END without a BEGIN, or a truncated last cert.
split_pem() {
    /usr/bin/awk -v dir="$2" '
        /-----BEGIN CERTIFICATE-----/ { if (w) { bad = 1; exit } cert = ""; w = 1 }
        w { cert = cert $0 ORS }
        /-----END CERTIFICATE-----/ {
            if (!w) { bad = 1; exit }
            f = dir "/" ++n ".pem"; printf "%s", cert > f; close(f); w = 0
        }
        END { if (bad || w) exit 1 }
    ' "$1"
}

# Print the SPKI sha256 of the PEM file $1. Fails if any step fails or the result
# is not exactly 64 lowercase hex characters.
spki_of() {
    setopt LOCAL_OPTIONS PIPE_FAIL
    local h
    h="$(/usr/bin/openssl x509 -inform pem -pubkey -noout <"$1" 2>/dev/null |
        /usr/bin/openssl pkey -pubin -outform der 2>/dev/null |
        /usr/bin/openssl dgst -sha256 -r 2>/dev/null)" || return 1
    h="${h%% *}"
    [[ ${#h} -eq 64 && "$h" != *[^0-9a-f]* ]] || return 1
    print -r -- "$h"
}

# Count certificates in $1 and report how many have a blocked key.
# Sets globals: scan_total, scan_blocked (comma-separated 1-based indices)
scan_bundle() {
    local file="$1" tmp f h n
    scan_total=0
    scan_blocked=""
    tmp="$(/usr/bin/mktemp -d)" || return 1
    [[ -n "$tmp" && -d "$tmp" ]] || return 1
    if ! split_pem "$file" "$tmp"; then
        /bin/rm -rf -- "$tmp"
        return 1
    fi
    for f in "$tmp"/*.pem(N); do
        n="${${f:t}%.pem}"
        if ! h="$(spki_of "$f")"; then
            /bin/rm -rf -- "$tmp"
            return 1
        fi
        (( scan_total++ ))
        if (( ${BLOCKED_SPKI[(Ie)$h]} )); then
            scan_blocked="${scan_blocked:+${scan_blocked},}${n}"
        fi
    done
    /bin/rm -rf -- "$tmp"
    (( scan_total > 0 ))
}

[[ -e "$BUNDLE" && ! -L "$BUNDLE" && -f "$BUNDLE" && -r "$BUNDLE" ]] || {
    log "ERROR: ${BUNDLE} is missing, unreadable, or not a regular file"
    exit 1
}

if ! scan_bundle "$BUNDLE"; then
    log "ERROR: could not parse ${BUNDLE}, leaving it untouched"
    exit 1
fi
total_before=$scan_total
blocked="$scan_blocked"

if [[ -z "$blocked" ]]; then
    log "No blocked public keys in ${BUNDLE} (${total_before} certificates). Nothing to do."
    exit 0
fi

typeset -a blocked_list=( ${(s:,:)blocked} )
removed=${#blocked_list}
log "Found ${removed} blocked certificate(s) in ${BUNDLE} (positions ${blocked} of ${total_before})"

new="${BUNDLE}.new.$$"
trap '/bin/rm -f -- "$new"' EXIT

# Drop each blocked PEM block together with the header comments just before it
/usr/bin/awk -v blocked="$blocked" '
    BEGIN { m = split(blocked, b, ","); for (i = 1; i <= m; i++) bad[b[i]] = 1 }
    /-----BEGIN CERTIFICATE-----/ { n++ }
    { buf = buf $0 ORS }
    /-----END CERTIFICATE-----/ { if (!(n in bad)) printf "%s", buf; buf = "" }
    END { printf "%s", buf }
' "$BUNDLE" >"$new" || {
    log "ERROR: filtering failed, ${BUNDLE} untouched"
    exit 1
}

# Validate the new file before it replaces anything
if ! scan_bundle "$new"; then
    log "ERROR: filtered file does not parse, ${BUNDLE} untouched"
    exit 1
fi
if [[ -n "$scan_blocked" ]]; then
    log "ERROR: filtered file still has blocked keys, ${BUNDLE} untouched"
    exit 1
fi
if (( scan_total != total_before - removed || scan_total < 50 )); then
    log "ERROR: unexpected certificate count (${scan_total}, expected $(( total_before - removed ))), ${BUNDLE} untouched"
    exit 1
fi

if (( EUID == 0 )); then
    /usr/sbin/chown root:wheel "$new" && /bin/chmod 644 "$new" || {
        log "ERROR: could not set ownership on the new file, ${BUNDLE} untouched"
        exit 1
    }
fi

if [[ ! -e "$BACKUP" ]]; then
    /bin/cp -p "$BUNDLE" "$BACKUP" || {
        log "ERROR: could not create the backup, ${BUNDLE} untouched"
        exit 1
    }
    log "Backup: ${BACKUP}"
fi

if ! /bin/mv -f "$new" "$BUNDLE"; then
    log "ERROR: could not replace ${BUNDLE}"
    exit 1
fi

# Verify what is now on disk
if ! scan_bundle "$BUNDLE" || [[ -n "$scan_blocked" ]]; then
    log "ERROR: ${BUNDLE} failed verification after the swap (restore from ${BACKUP})"
    exit 1
fi
log "VERIFIED: removed ${removed}; ${BUNDLE} now has ${scan_total} certificates, none blocked"
exit 0
