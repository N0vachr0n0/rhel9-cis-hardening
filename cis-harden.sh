#!/bin/bash
# =============================================================================
# patch_cis.sh — Script de remédiation CIS Benchmark unifié
# Sources : rapportsat.html (OpenSCAP) + rapport-cis-l1v4.html + scripts r1.sh–r12.sh
# Platform : RHEL 9 / CentOS Stream 9 / AlmaLinux 9 / Rocky Linux 9
# Contexte : VM rattachée à FreeIPA + Red Hat Satellite
# =============================================================================
# 29 SECTIONS :
#
#  ── Rapport OpenSCAP (rapportsat.html) ──
#  1  – Filesystem / Partitions          (/tmp sur partition séparée)
#  2  – Modules kernel désactivés        (cramfs, freevxfs, hfs, hfsplus, jffs2, usb-storage)
#  3  – Services à désactiver            (rpcbind, nftables, bluetooth, autofs)
#  4  – Sudo logfile                     (/var/log/sudo.log)
#  5  – Firewalld – trafic loopback
#  6  – Paramètres sysctl réseau         (21 paramètres IPv4/IPv6/kernel)
#  7  – Montage /dev/shm                 (nodev, noexec, nosuid)
#  8  – Montage /var                     (nodev, nosuid)
#  9  – Core dumps                       (désactivation)
#  10 – Fichiers world-writable          (suppression)
#  11 – Contrôle d'accès at/cron
#  12 – Durcissement SSH                 (13 directives)
#  ── Scripts r*.sh ──
#  13 – PAM – Mots de passe vides        (nullok désactivé)        [r1.sh]
#  14 – SSH – Mots de passe vides        (PermitEmptyPasswords no) [r2.sh]
#  15 – Bannières de connexion           (/etc/issue + /etc/issue.net) [r3.sh, r4.sh]
#  16 – Qualité des mots de passe        (dictcheck=1, maxrepeat=3) [r5.sh, r6.sh]
#  17 – Umask par défaut                 (/etc/bashrc, login.defs, /etc/profile) [r7-9.sh]
#  18 – Timeout de session interactive   (TMOUT=900)               [r10.sh]
#  19 – Permissions fichiers init users  (mode 0740 max)           [r11.sh]
#  20 – Journald – compression logs      (Compress=yes)            [r12.sh]
#  ── Findings CIS (rapportsat.html) ──
#  21 – AIDE                             (install + audit tools + cron ; --init commenté)
#  22 – Crypto Policy CIS               (NO-SSHCBC / NO-SSHWEAKCIPHERS / NO-WEAKMAC)
#  23 – sudo durcissement               (use_pty + timestamp_timeout=5)
#  24 – PAM faillock                    (deny=5 / unlock_time=900s)
#  25 – PAM pwquality                   (minlen=14 difok=2 minclass=4 maxsequence=3...)
#  26 – PAM historique MDP              (remember=24)
#  27 – Expiration compte               (PASS_MAX_DAYS=365 / INACTIVE=45 / chage)
#  28 – su restriction                  (sugroup vide + pam_wheel)
#  29 – Logging persistant              (systemd-journal-remote + Storage=persistent)
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'

log_ok()   { echo -e "${GREEN}[OK]${NC}    $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_err()  { echo -e "${RED}[ERR]${NC}   $*"; }
log_info() { echo -e "[INFO]  $*"; }

# ============================================================
# PARSING DES OPTIONS
# ============================================================
DRY_RUN=false
SECTION=""
YES=false
RUN_ALL=false
MAX_SECTION=29

usage() {
    cat <<EOF
${BOLD}Usage:${NC}
  $(basename "$0") [OPTIONS]

${BOLD}Description:${NC}
  Script de remédiation CIS Benchmark unifié (RHEL 9 / AlmaLinux 9 / Rocky Linux 9).
  Intègre le rapport OpenSCAP (rapportsat.html) et les scripts r1.sh à r12.sh.
  Doit être exécuté en tant que root. Sans option, affiche ce message.

${BOLD}Options:${NC}
  --run              Appliquer toutes les remédiations (sections 1 à ${MAX_SECTION})
  --section NUM      Appliquer uniquement la section NUM (1 à ${MAX_SECTION})
  --dry-run          Simuler sans appliquer aucun changement
  --yes              Ne pas demander de confirmation avant d'appliquer
  --help, -h         Afficher ce message d'aide

${BOLD}Sections disponibles:${NC}
  ── Rapport OpenSCAP ──────────────────────────────────────────────────────
  1  – Filesystem / Partitions (/tmp sur partition séparée)
  2  – Modules kernel désactivés (cramfs, freevxfs, hfs, hfsplus, jffs2, usb-storage)
  3  – Services désactivés (rpcbind, nftables, bluetooth, autofs)
  4  – Sudo logfile (/var/log/sudo.log)
  5  – Firewalld – trafic loopback (trusted + règles restrictives)
  6  – Paramètres sysctl réseau (21 params IPv4/IPv6/ASLR/ptrace)
  7  – Montage /dev/shm (nodev, noexec, nosuid)
  8  – Montage /var (nodev, nosuid)
  9  – Core dumps (ProcessSizeMax=0, Storage=none)
  10 – Fichiers world-writable (suppression chmod o-w)
  11 – Contrôle d'accès at/cron (allow/deny + permissions répertoires)
  12 – Durcissement SSH (13 directives : keepalive, root login, kex, etc.)
  ── Scripts r*.sh ─────────────────────────────────────────────────────────
  13 – PAM : désactiver nullok / mots de passe vides          [r1.sh]
  14 – SSH : PermitEmptyPasswords no                          [r2.sh]
  15 – Bannières de connexion (/etc/issue + /etc/issue.net)   [r3.sh, r4.sh]
  16 – Qualité mots de passe (dictcheck=1, maxrepeat=3)       [r5.sh, r6.sh]
  17 – Umask par défaut 027 (bashrc, login.defs, profile)     [r7.sh, r8.sh, r9.sh]
  18 – Timeout session interactive (TMOUT=900)                [r10.sh]
  19 – Permissions fichiers init utilisateurs (≤ 0740)        [r11.sh]
  20 – Journald : compression des logs (Compress=yes)         [r12.sh]
  ── Rapport CIS (rapportsat.html) ─────────────────────────────────────────
  21 – AIDE : intégrité fichiers (install + audit tools + cron ; --init commenté)
  22 – Crypto Policy : NO-SSHCBC / NO-SSHWEAKCIPHERS / NO-SSHWEAKMACS / NO-WEAKMAC
  23 – sudo : use_pty + timestamp_timeout=5
  24 – PAM faillock : deny=5 / unlock_time=900s (comptes locaux)
  25 – PAM pwquality : minlen=14 difok=2 minclass=4 maxsequence=3 dictcheck=1 enforce_for_root
  26 – PAM historique MDP : remember=24
  27 – Expiration compte : PASS_MAX_DAYS=365 / INACTIVE=45 / chage existants
  28 – su restriction : sugroup (vide) + pam_wheel
  29 – Logging : systemd-journal-remote + journald Storage=persistent

${BOLD}Exemples:${NC}
  $(basename "$0") --help
  $(basename "$0") --dry-run --run
  $(basename "$0") --run
  $(basename "$0") --run --yes
  $(basename "$0") --section 16 --yes
  $(basename "$0") --section 24 --yes
  $(basename "$0") --section 21 --yes  # AIDE (sans --init)

${BOLD}AVERTISSEMENT:${NC}
  Un redémarrage est nécessaire pour les modules kernel et certains sysctl.
EOF
}

if [[ $# -eq 0 ]]; then
    usage; exit 0
fi

while [[ $# -gt 0 ]]; do
    case "$1" in
        --run)        RUN_ALL=true;      shift ;;
        --section)    SECTION="$2";      shift 2 ;;
        --dry-run)    DRY_RUN=true;      shift ;;
        --yes)        YES=true;          shift ;;
        --help|-h)    usage; exit 0 ;;
        *) echo -e "${RED}Option inconnue: $1${NC}"; usage; exit 1 ;;
    esac
done

if ! $RUN_ALL && [[ -z "$SECTION" ]]; then
    log_err "Aucune action spécifiée. Utilisez --run ou --section NUM."
    usage; exit 1
fi

if [[ -n "$SECTION" ]]; then
    if ! [[ "$SECTION" =~ ^[0-9]+$ ]] || (( SECTION < 1 || SECTION > MAX_SECTION )); then
        log_err "Section invalide: '$SECTION'. Valeurs acceptées: 1 à ${MAX_SECTION}."
        exit 1
    fi
fi

if [[ $EUID -ne 0 ]]; then
    log_err "Ce script doit être exécuté en tant que root."
    exit 1
fi

# Dry-run : affiche la commande sans l'exécuter
run_cmd() {
    if $DRY_RUN; then
        echo -e "${BLUE}[DRY-RUN]${NC} $*"
    else
        eval "$@"
    fi
}

# Confirmation interactive
if ! $YES && ! $DRY_RUN; then
    echo -e "${YELLOW}${BOLD}"
    echo "  ╔══════════════════════════════════════════════════════════╗"
    echo "  ║          AVERTISSEMENT – MODIFICATION SYSTÈME            ║"
    echo "  ║                                                          ║"
    echo "  ║  Ce script va modifier la configuration du système.     ║"
    echo "  ║  Testez d'abord dans un environnement non-production.   ║"
    echo "  ╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    [[ -n "$SECTION" ]] && echo "  Section ciblée : ${SECTION}" \
                        || echo "  Sections ciblées : toutes (1 à ${MAX_SECTION})"
    echo ""
    read -r -p "  Confirmer l'application des remédiations ? [oui/NON] : " CONFIRM
    [[ "${CONFIRM,,}" == "oui" ]] || { echo "Abandon."; exit 0; }
fi

$DRY_RUN && echo -e "${BLUE}${BOLD}[MODE DRY-RUN] Aucun changement ne sera appliqué.${NC}"

# ============================================================
# FONCTIONS UTILITAIRES
# ============================================================

# Persiste un paramètre sysctl dans /etc/sysctl.conf
set_sysctl() {
    local key="$1" value="$2"
    local SYSCONFIG_FILE="/etc/sysctl.conf"
    for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do
        [[ -f "$f" ]] || continue
        [[ "$(readlink -f "$f")" == "/etc/sysctl.conf" ]] && continue
        local matching_list
        matching_list=$(grep -P "^(?!#).*[\s]*${key//./\\.}.*$" "$f" 2>/dev/null | uniq) || true
        if [[ -n "$matching_list" ]]; then
            while IFS= read -r entry; do
                local escaped_entry
                escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
                sed -i --follow-symlinks "s/^${escaped_entry}$/# &/g" "$f"
            done <<< "$matching_list"
        fi
    done
    /sbin/sysctl -q -n -w "${key}=${value}" 2>/dev/null || true
    local stripped_key formatted_output
    stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^${key}")
    formatted_output="${stripped_key} = ${value}"
    if LC_ALL=C grep -q -m 1 -i -e "^${key}\\>" "${SYSCONFIG_FILE}" 2>/dev/null; then
        local escaped_out
        escaped_out=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
        LC_ALL=C sed -i --follow-symlinks "s/^${key}\\>.*/${escaped_out}/gi" "${SYSCONFIG_FILE}"
    else
        [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]] && \
            LC_ALL=C sed -i --follow-symlinks '$a\' "${SYSCONFIG_FILE}"
        printf '# CIS Hardening: %s\n%s\n' "${key}" "${formatted_output}" >> "${SYSCONFIG_FILE}"
    fi
}

# Blackliste un module kernel
disable_kmod() {
    local mod="$1" conf="/etc/modprobe.d/${1}.conf"
    if LC_ALL=C grep -q -m 1 "^install ${mod}" "$conf" 2>/dev/null; then
        sed -i "s#^install ${mod}.*#install ${mod} /bin/false#g" "$conf"
    else
        { echo ""; echo "# Disabled per CIS requirements"; echo "install ${mod} /bin/false"; } >> "$conf"
    fi
    LC_ALL=C grep -q -m 1 "^blacklist ${mod}$" "$conf" 2>/dev/null || echo "blacklist ${mod}" >> "$conf"
}

# Configure une directive dans un fichier drop-in sshd_config.d
set_sshd_option() {
    local directive="$1" value="$2" dropfile="$3"
    local confdir="/etc/ssh/sshd_config.d"
    local fullpath="${confdir}/${dropfile}"
    mkdir -p "$confdir"
    touch "$fullpath"; chmod 0600 "$fullpath"
    LC_ALL=C sed -i "/^\s*${directive}\s\+/Id" "/etc/ssh/sshd_config"
    LC_ALL=C sed -i "/^\s*${directive}\s\+/Id" "${confdir}"/*.conf 2>/dev/null || true
    sed -i -e '$a\' "$fullpath"
    local bak="${fullpath}.bak"
    cp "$fullpath" "$bak"
    printf '%s\n' "${directive} ${value}" > "$fullpath"
    cat "$bak" >> "$fullpath"
    rm -f "$bak"
}

# Persiste une valeur dans /etc/security/pwquality.conf
set_pwquality() {
    local key="$1" value="$2" cce="$3"
    local conf="/etc/security/pwquality.conf"
    # Supprimer les éventuelles occurrences dans pwquality.conf.d/
    if grep -sq "${key}" /etc/security/pwquality.conf.d/*.conf 2>/dev/null; then
        sed -i "/${key}/d" /etc/security/pwquality.conf.d/*.conf
    fi
    local stripped_key formatted_output
    stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^${key}")
    formatted_output="${stripped_key} = ${value}"
    if LC_ALL=C grep -q -m 1 -i -e "^${key}\\>" "$conf" 2>/dev/null; then
        local esc
        esc=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
        LC_ALL=C sed -i --follow-symlinks "s/^${key}\\>.*/${esc}/gi" "$conf"
    else
        [[ -s "$conf" ]] && [[ -n "$(tail -c 1 -- "$conf" || true)" ]] && \
            LC_ALL=C sed -i --follow-symlinks '$a\' "$conf"
        printf '# Per %s: Set %s in %s\n%s\n' "${cce}" "${formatted_output}" "$conf" "${formatted_output}" >> "$conf"
    fi
}

# ============================================================
# SECTIONS 1-12 (rapport OpenSCAP)
# ============================================================

section_1() {
    echo "--- SECTION 1: Filesystem & Partitions ---"
    log_info "Ensure /tmp Located On Separate Partition"
    if findmnt --kernel /tmp >/dev/null 2>&1 && \
       [[ "$(findmnt -n -o FSTYPE /tmp 2>/dev/null)" == "tmpfs" ]]; then
        log_ok "/tmp déjà monté sur tmpfs"
    else
        if systemctl is-enabled tmp.mount &>/dev/null; then
            log_ok "tmp.mount déjà activé"
        else
            run_cmd "systemctl enable --now tmp.mount" && \
                log_ok "tmp.mount activé (tmpfs)" || \
                log_warn "/tmp: partition physique séparée requise — configuration manuelle"
        fi
    fi
}

section_2() {
    echo "--- SECTION 2: Modules kernel désactivés ---"
    for mod in cramfs freevxfs hfs hfsplus jffs2 usb-storage; do
        log_info "Disable module: ${mod}"
        if $DRY_RUN; then
            echo -e "${BLUE}[DRY-RUN]${NC} disable_kmod ${mod} → /etc/modprobe.d/${mod}.conf"
        else
            disable_kmod "$mod"
            if lsmod | grep -q "^${mod//-/_}\b" 2>/dev/null; then
                modprobe -r "${mod}" 2>/dev/null || true
                log_warn "${mod} déchargé du noyau en live"
            fi
        fi
        log_ok "Module ${mod} blacklisté"
    done
}

section_3() {
    echo "--- SECTION 3: Services à désactiver ---"
    _svc_off() {
        local svc="$1" pkg="$2"
        log_info "Disable: ${svc}"
        if [[ -n "$pkg" ]] && ! rpm -q --quiet "$pkg" 2>/dev/null; then
            log_warn "${pkg} non installé — ${svc} ignoré"; return
        fi
        if $DRY_RUN; then
            echo -e "${BLUE}[DRY-RUN]${NC} systemctl stop/disable/mask ${svc}"; return
        fi
        systemctl is-system-running 2>/dev/null | grep -qv "offline" && \
            systemctl stop "${svc}.service" 2>/dev/null || true
        systemctl disable "${svc}.service" 2>/dev/null || true
        systemctl mask   "${svc}.service" 2>/dev/null || true
        if systemctl -q list-unit-files "${svc}.socket" 2>/dev/null; then
            systemctl stop "${svc}.socket" 2>/dev/null || true
            systemctl mask "${svc}.socket" 2>/dev/null || true
        fi
        systemctl reset-failed "${svc}.service" 2>/dev/null || true
        log_ok "${svc} arrêté, désactivé et masqué"
    }
    _svc_off "rpcbind"  "rpcbind"
    if rpm --quiet -q firewalld 2>/dev/null && rpm --quiet -q nftables 2>/dev/null; then
        _svc_off "nftables" ""
    else
        log_warn "nftables: firewalld ou nftables absent — ignoré"
    fi
    _svc_off "bluetooth" "bluez"
    _svc_off "autofs"    "autofs"
}

section_4() {
    echo "--- SECTION 4: Sudo logfile ---"
    log_info "Ensure Sudo Logfile Exists"
    rpm --quiet -q sudo 2>/dev/null || { log_warn "sudo non installé — ignoré"; return; }
    local logfile='/var/log/sudo.log'
    if $DRY_RUN; then
        echo -e "${BLUE}[DRY-RUN]${NC} Defaults logfile=${logfile} → /etc/sudoers"; return
    fi
    if /usr/sbin/visudo -qcf /etc/sudoers 2>/dev/null; then
        cp /etc/sudoers /etc/sudoers.bak
        if ! grep -P '^[\s]*Defaults\b[^!\n]*\blogfile\s*=' /etc/sudoers &>/dev/null; then
            echo "Defaults logfile=${logfile}" >> /etc/sudoers
        elif ! grep -P "^[\s]*Defaults.*\blogfile=${logfile}\b" /etc/sudoers &>/dev/null; then
            local esc="${logfile//$'/'/$'\/'}"
            sed -Ei "s|(^[\s]*Defaults.*\blogfile=)[-]?.+(\b.*$)|\1${esc}\2|" /etc/sudoers
        fi
        if /usr/sbin/visudo -qcf /etc/sudoers 2>/dev/null; then
            rm -f /etc/sudoers.bak
            log_ok "sudo logfile: ${logfile}"
        else
            log_err "sudoers invalide après modification — restauration"
            mv /etc/sudoers.bak /etc/sudoers
        fi
    else
        log_err "sudoers déjà invalide — aucune modification"
    fi
}

section_5() {
    echo "--- SECTION 5: Firewalld – trafic loopback ---"
    rpm --quiet -q firewalld 2>/dev/null || { log_warn "firewalld non installé — ignoré"; return; }
    systemctl is-active firewalld &>/dev/null || {
        log_warn "firewalld inactif — démarrez-le et relancez cette section"; return; }
    local r4='rule family=ipv4 source address="127.0.0.1" destination not address="127.0.0.1" drop'
    local r6='rule family=ipv6 source address="::1" destination not address="::1" drop'
    if $DRY_RUN; then
        echo -e "${BLUE}[DRY-RUN]${NC} firewall-cmd --permanent --zone=trusted --add-interface=lo"
        echo -e "${BLUE}[DRY-RUN]${NC} firewall-cmd --permanent --zone=trusted --add-rich-rule='${r4}'"
        echo -e "${BLUE}[DRY-RUN]${NC} firewall-cmd --permanent --zone=trusted --add-rich-rule='${r6}'"
        echo -e "${BLUE}[DRY-RUN]${NC} firewall-cmd --reload"
    else
        firewall-cmd --permanent --zone=trusted --add-interface=lo 2>/dev/null || true
        log_ok "lo → zone trusted"
        firewall-cmd --permanent --zone=trusted --add-rich-rule="${r4}" 2>/dev/null || true
        firewall-cmd --permanent --zone=trusted --add-rich-rule="${r6}" 2>/dev/null || true
        firewall-cmd --reload 2>/dev/null || true
        log_ok "Règles loopback restrictives appliquées"
    fi
}

section_6() {
    echo "--- SECTION 6: Paramètres sysctl réseau ---"
    declare -A P=(
        ["net.ipv6.conf.all.accept_ra"]="0"
        ["net.ipv6.conf.all.accept_redirects"]="0"
        ["net.ipv6.conf.all.accept_source_route"]="0"
        ["net.ipv6.conf.all.forwarding"]="0"
        ["net.ipv6.conf.default.accept_ra"]="0"
        ["net.ipv6.conf.default.accept_redirects"]="0"
        ["net.ipv6.conf.default.accept_source_route"]="0"
        ["net.ipv4.conf.all.accept_redirects"]="0"
        ["net.ipv4.conf.all.accept_source_route"]="0"
        ["net.ipv4.conf.all.rp_filter"]="1"
        ["net.ipv4.conf.all.secure_redirects"]="0"
        ["net.ipv4.conf.all.send_redirects"]="0"
        ["net.ipv4.conf.default.accept_redirects"]="0"
        ["net.ipv4.conf.default.rp_filter"]="1"
        ["net.ipv4.conf.default.secure_redirects"]="0"
        ["net.ipv4.conf.default.send_redirects"]="0"
        ["net.ipv4.icmp_echo_ignore_broadcasts"]="1"
        ["net.ipv4.ip_forward"]="0"
        ["net.ipv4.tcp_syncookies"]="1"
        ["kernel.randomize_va_space"]="2"
        ["kernel.yama.ptrace_scope"]="1"
    )
    for key in "${!P[@]}"; do
        local val="${P[$key]}"
        if $DRY_RUN; then
            echo -e "${BLUE}[DRY-RUN]${NC} sysctl -w ${key}=${val}"
        else
            set_sysctl "$key" "$val"
        fi
        log_ok "sysctl ${key} = ${val}"
    done
}

section_7() {
    echo "--- SECTION 7: Montage /dev/shm ---"
    local re
    re="$(printf "^[[:space:]]*[^#].*[[:space:]]%s[[:space:]]" /dev/shm)"
    for opt in nodev noexec nosuid; do
        log_info "Add ${opt} to /dev/shm"
        if $DRY_RUN; then
            echo -e "${BLUE}[DRY-RUN]${NC} Ajout ${opt} dans /etc/fstab pour /dev/shm"; continue
        fi
        if ! grep -q "$re" /etc/fstab; then
            local prev
            prev=$(grep "$re" /etc/mtab 2>/dev/null | head -1 | awk '{print $4}' \
                | sed -E "s/(rw|defaults|seclabel|${opt})(,|$)//g;s/,$//" || echo "")
            [[ -n "$prev" ]] && prev+=","
            echo "tmpfs /dev/shm tmpfs defaults,${prev}${opt} 0 0" >> /etc/fstab
            log_ok "/dev/shm: nouveau fstab + ${opt}"
        elif ! grep "$re" /etc/fstab | grep -q "$opt"; then
            local prev; prev=$(grep "$re" /etc/fstab | awk '{print $4}')
            sed -i "s|\(${re}.*${prev}\)|\1,${opt}|" /etc/fstab
            log_ok "/dev/shm: option ${opt} ajoutée"
        else
            log_ok "/dev/shm: ${opt} déjà présent"
        fi
    done
    ! $DRY_RUN && mountpoint -q /dev/shm 2>/dev/null && \
        { mount -o remount --target /dev/shm 2>/dev/null && log_ok "/dev/shm remonté" || \
          log_warn "/dev/shm: remontage échoué — redémarrage requis"; } || true
}

section_8() {
    echo "--- SECTION 8: Montage /var ---"
    if ! { findmnt --kernel "/var" >/dev/null 2>&1 || findmnt --fstab "/var" >/dev/null 2>&1; }; then
        log_warn "/var non sur partition séparée — non applicable"; return
    fi
    local re
    re="$(printf "^[[:space:]]*[^#].*[[:space:]]%s[[:space:]]" /var)"
    for opt in nodev nosuid; do
        log_info "Add ${opt} to /var"
        if $DRY_RUN; then
            echo -e "${BLUE}[DRY-RUN]${NC} Ajout ${opt} dans /etc/fstab pour /var"; continue
        fi
        if ! grep -q "$re" /etc/fstab; then
            log_warn "/var absent de /etc/fstab — configuration manuelle requise"
        elif ! grep "$re" /etc/fstab | grep -q "$opt"; then
            local prev; prev=$(grep "$re" /etc/fstab | awk '{print $4}')
            sed -i "s|\(${re}.*${prev}\)|\1,${opt}|" /etc/fstab
            log_ok "/var: option ${opt} ajoutée"
        else
            log_ok "/var: ${opt} déjà présent"
        fi
    done
    ! $DRY_RUN && mountpoint -q /var 2>/dev/null && \
        { mount -o remount --target /var 2>/dev/null && log_ok "/var remonté" || \
          log_warn "/var: remontage échoué — redémarrage requis"; } || true
}

section_9() {
    echo "--- SECTION 9: Core dumps ---"
    rpm --quiet -q systemd 2>/dev/null || { log_warn "systemd non installé — ignoré"; return; }
    local d="/etc/systemd/coredump.conf.d"
    local conf="${d}/complianceascode_hardening.conf"
    for kv in "ProcessSizeMax=0" "Storage=none"; do
        local key="${kv%%=*}" val="${kv#*=}"
        log_info "coredump ${key}=${val}"
        if $DRY_RUN; then
            echo -e "${BLUE}[DRY-RUN]${NC} ${key}=${val} dans ${conf}"; continue
        fi
        mkdir -p "$d"
        local found=false f
        for f in "${conf}" "${d}"/*.conf /etc/systemd/coredump.conf; do
            [[ -f "$f" ]] || continue
            if grep -qzosP "[[:space:]]*\[Coredump\]([^\n\[]*\n+)+?[[:space:]]*${key}" "$f" 2>/dev/null; then
                grep -qPz "${key}=${val}" "$f" 2>/dev/null || \
                    sed -i "s/${key}[^(\n)]*/${key}=${val}/" "$f"
                found=true; break
            elif grep -qs "[[:space:]]*\[Coredump\]" "$f" 2>/dev/null; then
                sed -i "/[[:space:]]*\[Coredump\]/a ${key}=${val}" "$f"
                found=true; break
            fi
        done
        $found || printf '[Coredump]\n%s\n' "${key}=${val}" >> "$conf"
        log_ok "coredump ${key}=${val}"
    done
}

section_10() {
    echo "--- SECTION 10: Fichiers world-writable ---"
    log_info "Ensure No World-Writable Files Exist"
    if $DRY_RUN; then
        echo -e "${BLUE}[DRY-RUN]${NC} find <partitions> -xdev -type f -perm -002 -exec chmod o-w {} \\;"; return
    fi
    local FNODEV PARTS PART
    FNODEV=$(awk '/nodev/ { print $2 }' /proc/filesystems | paste -sd,)
    PARTS=$(findmnt -n -l -k -it "$FNODEV" 2>/dev/null | awk '{print $1}' | grep -v "/sysroot" || true)
    for PART in $PARTS; do
        find "${PART}" -xdev -type f -perm -002 -exec chmod o-w {} \; 2>/dev/null
    done
    grep "^tmpfs /tmp" /proc/mounts &>/dev/null && \
        find /tmp -xdev -type f -perm -002 -exec chmod o-w {} \; 2>/dev/null || true
    log_ok "Fichiers world-writable corrigés"
}

section_11() {
    echo "--- SECTION 11: Contrôle d'accès at/cron ---"
    if $DRY_RUN; then
        echo -e "${BLUE}[DRY-RUN]${NC} touch /etc/at.allow (0640) ; rm /etc/at.deny"
        echo -e "${BLUE}[DRY-RUN]${NC} touch /etc/cron.allow (0600) ; rm /etc/cron.deny"
        echo -e "${BLUE}[DRY-RUN]${NC} chmod cron dirs + /etc/crontab"; return
    fi
    touch /etc/at.allow;   chown 0 /etc/at.allow;   chmod 0640 /etc/at.allow
    log_ok "/etc/at.allow (0640, root)"
    [[ -f /etc/at.deny ]]   && { rm /etc/at.deny;   log_ok "/etc/at.deny supprimé";  } || log_ok "/etc/at.deny absent"
    touch /etc/cron.allow; chown 0 /etc/cron.allow; chmod 0600 /etc/cron.allow
    log_ok "/etc/cron.allow (0600, root)"
    [[ -f /etc/cron.deny ]] && { rm /etc/cron.deny; log_ok "/etc/cron.deny supprimé";} || log_ok "/etc/cron.deny absent"
    for d in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly; do
        find -H "$d/" -maxdepth 0 -perm /u+s,g+xwrs,o+xwrt -type d \
            -exec chmod u-s,g-xwrs,o-xwrt {} \; 2>/dev/null
    done
    [[ -f /etc/crontab ]] && chmod u-xs,g-xwrs,o-xwrt /etc/crontab
    log_ok "Permissions cron corrigées"
}

section_12() {
    echo "--- SECTION 12: Durcissement SSH ---"
    rpm --quiet -q openssh-server 2>/dev/null || { log_warn "openssh-server non installé — ignoré"; return; }
    declare -A H=(
        ["ClientAliveCountMax"]="1"
        ["ClientAliveInterval"]="300"
        ["LoginGraceTime"]="60"
        ["LogLevel"]="VERBOSE"
        ["MaxAuthTries"]="4"
        ["MaxSessions"]="10"
        ["MaxStartups"]="10:30:60"
        ["Banner"]="/etc/issue.net"
        ["PermitRootLogin"]="no"
        ["KexAlgorithms"]="-diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1"
    )
    declare -A D=(
        ["HostbasedAuthentication"]="no"
        ["IgnoreRhosts"]="yes"
        ["PermitUserEnvironment"]="no"
    )
    if $DRY_RUN; then
        for k in "${!H[@]}"; do echo -e "${BLUE}[DRY-RUN]${NC} SSH: ${k} ${H[$k]}"; done
        for k in "${!D[@]}"; do echo -e "${BLUE}[DRY-RUN]${NC} SSH: ${k} ${D[$k]}"; done
        return
    fi
    mkdir -p /etc/ssh/sshd_config.d
    for k in "${!H[@]}"; do
        set_sshd_option "$k" "${H[$k]}" "00-complianceascode-hardening.conf"
        log_ok "SSH: ${k} ${H[$k]}"
    done
    for k in "${!D[@]}"; do
        set_sshd_option "$k" "${D[$k]}" "01-complianceascode-reinforce-os-defaults.conf"
        log_ok "SSH: ${k} ${D[$k]}"
    done
    if sshd -t 2>/dev/null; then
        systemctl reload sshd 2>/dev/null || systemctl restart sshd 2>/dev/null || true
        log_ok "SSHD rechargé"
    else
        log_err "Config SSH invalide après modification — vérifiez avec: sshd -t"
    fi
}

# ============================================================
# SECTIONS 13-20 (scripts r*.sh)
# ============================================================

section_13() {
    # r1.sh – Prevent Login to Accounts With Empty Password (PAM nullok)
    echo "--- SECTION 13: PAM – Désactivation nullok (mots de passe vides) ---"
    log_info "Prevent Login to Accounts With Empty Password"
    rpm --quiet -q kernel-core 2>/dev/null || { log_warn "kernel-core absent — ignoré"; return; }
    if $DRY_RUN; then
        echo -e "${BLUE}[DRY-RUN]${NC} authselect enable-feature without-nullok (ou sed pam_unix.so)"
        return
    fi
    if [ -f /usr/bin/authselect ]; then
        if ! authselect check 2>/dev/null; then
            log_err "authselect: profil corrompu ou non sélectionné — aucune modification"
            return
        fi
        authselect enable-feature without-nullok
        authselect apply-changes -b
    else
        for pam_file in /etc/pam.d/system-auth /etc/pam.d/password-auth; do
            for ctx in auth password; do
                if grep -qP "^\s*${ctx}\s+sufficient\s+pam_unix.so\s.*\bnullok\b" "$pam_file" 2>/dev/null; then
                    sed -i -E --follow-symlinks \
                        "s/(.*${ctx}.*sufficient.*pam_unix.so.*)\bnullok\b=?[[:alnum:]]*(.*)/\1\2/g" \
                        "$pam_file"
                fi
            done
        done
    fi
    log_ok "PAM nullok désactivé"
}

section_14() {
    # r2.sh – Disable SSH Access via Empty Passwords
    echo "--- SECTION 14: SSH – PermitEmptyPasswords no ---"
    log_info "Disable SSH Access via Empty Passwords"
    rpm --quiet -q kernel-core 2>/dev/null || { log_warn "kernel-core absent — ignoré"; return; }
    rpm --quiet -q openssh-server 2>/dev/null || { log_warn "openssh-server absent — ignoré"; return; }
    if $DRY_RUN; then
        echo -e "${BLUE}[DRY-RUN]${NC} sshd_config: PermitEmptyPasswords no"; return
    fi
    set_sshd_option "PermitEmptyPasswords" "no" "01-complianceascode-reinforce-os-defaults.conf"
    log_ok "SSH: PermitEmptyPasswords no"
    if sshd -t 2>/dev/null; then
        systemctl reload sshd 2>/dev/null || systemctl restart sshd 2>/dev/null || true
        log_ok "SSHD rechargé"
    else
        log_err "Config SSH invalide — vérifiez avec: sshd -t"
    fi
}

section_15() {
    # r3.sh + r4.sh – Login banners (/etc/issue, /etc/issue.net)
    echo "--- SECTION 15: Bannières de connexion ---"
    local banner_text='Authorized users only. All activity may be monitored and reported.'
    rpm --quiet -q kernel-core 2>/dev/null || { log_warn "kernel-core absent — ignoré"; return; }
    if $DRY_RUN; then
        echo -e "${BLUE}[DRY-RUN]${NC} echo '${banner_text}' > /etc/issue"
        echo -e "${BLUE}[DRY-RUN]${NC} echo '${banner_text}' > /etc/issue.net"
        return
    fi
    # r3.sh – Local login banner
    log_info "Ensure Local Login Warning Banner Is Configured Properly"
    echo "$banner_text" > /etc/issue
    log_ok "/etc/issue configuré"
    # r4.sh – Remote login banner
    log_info "Ensure Remote Login Warning Banner Is Configured Properly"
    echo "$banner_text" > /etc/issue.net
    log_ok "/etc/issue.net configuré"
}

section_16() {
    # r5.sh + r6.sh – Password quality (dictcheck, maxrepeat)
    echo "--- SECTION 16: Qualité des mots de passe ---"
    if ! rpm --quiet -q kernel-core 2>/dev/null || ! rpm --quiet -q libpwquality 2>/dev/null; then
        log_warn "kernel-core ou libpwquality absent — ignoré"; return
    fi
    if $DRY_RUN; then
        echo -e "${BLUE}[DRY-RUN]${NC} pwquality: dictcheck = 1"
        echo -e "${BLUE}[DRY-RUN]${NC} pwquality: maxrepeat = 3"
        return
    fi
    # r5.sh – Prevent Use of Dictionary Words
    log_info "Ensure PAM Enforces Password Requirements - Prevent Dictionary Words"
    set_pwquality "dictcheck" "1" "CCE-88413-0"
    log_ok "pwquality: dictcheck = 1"
    # r6.sh – Maximum Consecutive Repeating Characters
    log_info "Set Password Maximum Consecutive Repeating Characters"
    set_pwquality "maxrepeat" "3" "CCE-83567-8"
    log_ok "pwquality: maxrepeat = 3"
}

section_17() {
    # r7.sh + r8.sh + r9.sh – Default umask 027
    echo "--- SECTION 17: Umask par défaut (027) ---"
    local umask_val='027'
    if $DRY_RUN; then
        echo -e "${BLUE}[DRY-RUN]${NC} umask ${umask_val} → /etc/bashrc"
        echo -e "${BLUE}[DRY-RUN]${NC} UMASK ${umask_val} → /etc/login.defs"
        echo -e "${BLUE}[DRY-RUN]${NC} umask ${umask_val} → /etc/profile[.d/*.sh]"
        return
    fi
    # r7.sh – /etc/bashrc
    if rpm --quiet -q bash 2>/dev/null; then
        log_info "Ensure the Default Bash Umask is Set Correctly"
        if grep -q "^[^#]*\bumask" /etc/bashrc 2>/dev/null; then
            sed -i -E "s/^([^#]*\bumask)[[:space:]]+[[:digit:]]+/\1 ${umask_val}/g" /etc/bashrc
        else
            echo "umask ${umask_val}" >> /etc/bashrc
        fi
        log_ok "umask ${umask_val} dans /etc/bashrc"
    fi
    # r8.sh – /etc/login.defs
    if rpm --quiet -q shadow-utils 2>/dev/null; then
        log_info "Ensure the Default Umask is Set Correctly in login.defs"
        local stripped_key formatted_output
        stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^UMASK")
        formatted_output="${stripped_key} ${umask_val}"
        if LC_ALL=C grep -q -m 1 -i -e "^UMASK\\>" /etc/login.defs; then
            LC_ALL=C sed -i --follow-symlinks \
                "s/^UMASK\\>.*/${formatted_output}/gi" /etc/login.defs
        else
            [[ -s /etc/login.defs ]] && \
                LC_ALL=C sed -i --follow-symlinks '$a\' /etc/login.defs
            printf '# Per CCE-83647-8: Set %s in /etc/login.defs\n%s\n' \
                "$formatted_output" "$formatted_output" >> /etc/login.defs
        fi
        log_ok "UMASK ${umask_val} dans /etc/login.defs"
    fi
    # r9.sh – /etc/profile + /etc/profile.d/*.sh
    log_info "Ensure the Default Umask is Set Correctly in /etc/profile"
    readarray -t pfiles < <(find /etc/profile.d/ -type f \( -name '*.sh' -o -name 'sh.local' \) 2>/dev/null)
    for pf in "${pfiles[@]}" /etc/profile; do
        grep -qE '^[^#]*umask' "$pf" 2>/dev/null && \
            sed -i -E "s/^(\s*umask\s*)[0-7]+/\1${umask_val}/g" "$pf" || true
    done
    grep -qrE '^[^#]*umask' /etc/profile* 2>/dev/null || \
        echo "umask ${umask_val}" >> /etc/profile
    log_ok "umask ${umask_val} dans /etc/profile[.d]"
}

section_18() {
    # r10.sh – Set Interactive Session Timeout (TMOUT=900)
    echo "--- SECTION 18: Timeout de session interactive ---"
    log_info "Set Interactive Session Timeout (TMOUT=900)"
    rpm --quiet -q kernel-core 2>/dev/null || { log_warn "kernel-core absent — ignoré"; return; }
    local tmout_val='900'
    if $DRY_RUN; then
        echo -e "${BLUE}[DRY-RUN]${NC} typeset -xr TMOUT=${tmout_val} → /etc/profile.d/tmout.sh"; return
    fi
    local found=0
    for f in /etc/profile /etc/profile.d/*.sh; do
        [[ -f "$f" ]] || continue
        if grep --silent '^[^#].*TMOUT' "$f"; then
            sed -i -E "s/^(.*)TMOUT\s*=\s*(\w|\$)*(.*)$/typeset -xr TMOUT=${tmout_val}\3/g" "$f"
            found=1
        fi
    done
    if [[ $found -eq 0 ]]; then
        printf '\n# Set TMOUT per CIS requirements\ntypeset -xr TMOUT=%s\n' \
            "${tmout_val}" >> /etc/profile.d/tmout.sh
    fi
    log_ok "TMOUT=${tmout_val} configuré dans /etc/profile.d/tmout.sh"
}

section_19() {
    # r11.sh – Ensure All User Initialization Files Have Mode 0740 Or Less Permissive
    echo "--- SECTION 19: Permissions fichiers init utilisateurs ---"
    log_info "Ensure All User Initialization Files Have Mode 0740 Or Less Permissive"
    if $DRY_RUN; then
        echo -e "${BLUE}[DRY-RUN]${NC} chmod u-s,g-wxs,o= ~/.* pour tous les utilisateurs interactifs"
        return
    fi
    local regex='^\.[\w\- ]+$'
    local ignored='nobody|nfsnobody'
    readarray -t users  < <(awk -F: '$3>=1000 {print $1}' /etc/passwd)
    readarray -t homes  < <(awk -F: '$3>=1000 {print $6}' /etc/passwd)
    readarray -t shells < <(awk -F: '$3>=1000 {print $7}' /etc/passwd)
    for (( i=0; i<"${#users[@]}"; i++ )); do
        grep -qP "$ignored" <<< "${users[$i]}" && continue
        [[ "${shells[$i]}" == "/sbin/nologin" ]] && continue
        readarray -t ifiles < <(find "${homes[$i]}" -maxdepth 1 \
            -exec basename {} \; 2>/dev/null | grep -P "$regex")
        for file in "${ifiles[@]}"; do
            [[ -e "${homes[$i]}/${file}" ]] && \
                chmod u-s,g-wxs,o= "${homes[$i]}/${file}" 2>/dev/null || true
        done
    done
    log_ok "Permissions fichiers init utilisateurs corrigées (≤ 0740)"
}

section_20() {
    # r12.sh – Ensure journald is configured to compress large log files
    echo "--- SECTION 20: Journald – compression des logs ---"
    log_info "Ensure journald is configured to compress large log files"
    rpm --quiet -q kernel-core 2>/dev/null || { log_warn "kernel-core absent — ignoré"; return; }
    local jdir="/etc/systemd/journald.conf.d"
    local jconf="${jdir}/complianceascode_hardening.conf"
    if $DRY_RUN; then
        echo -e "${BLUE}[DRY-RUN]${NC} Compress=yes → ${jconf}"; return
    fi
    local found=false f
    for f in "${jconf}" "${jdir}"/*.conf /etc/systemd/journald.conf; do
        [[ -f "$f" ]] || continue
        if grep -qzosP "[[:space:]]*\[Journal\]([^\n\[]*\n+)+?[[:space:]]*Compress" "$f" 2>/dev/null; then
            grep -qPz "Compress=yes" "$f" 2>/dev/null || sed -i "s/Compress[^(\n)]*/Compress=yes/" "$f"
            found=true; break
        elif grep -qs "[[:space:]]*\[Journal\]" "$f" 2>/dev/null; then
            sed -i "/[[:space:]]*\[Journal\]/a Compress=yes" "$f"
            found=true; break
        fi
    done
    if ! $found; then
        mkdir -p "$jdir"
        printf '[Journal]\nCompress=yes\n' >> "$jconf"
    fi
    log_ok "journald: Compress=yes"
}
# ============================================================
# SECTIONS 21-29 (Findings CIS rapportsat.html)
# ============================================================

section_21() {
    echo "--- SECTION 21: AIDE — Contrôle d'intégrité des fichiers ---"
    log_info "Install + configure audit tools + cron 04h05"
    log_warn "AIDE --init commenté — à exécuter manuellement en fenêtre de maintenance"
    if $DRY_RUN; then
        echo -e "${BLUE}[DRY-RUN]${NC} dnf install aide"
        echo -e "${BLUE}[DRY-RUN]${NC} Configure /etc/aide.conf (audit tools)"
        echo -e "${BLUE}[DRY-RUN]${NC} Ajouter cron 04h05 /usr/sbin/aide --check"
        return
    fi

    # Remediation is applicable only in certain platforms
    if rpm --quiet -q kernel-core; then

    if ! rpm -q --quiet "aide" ; then
        dnf install -y "aide"
    fi

    else
        >&2 echo 'Remediation is not applicable, nothing was done'
    fi

    # Remediation is applicable only in certain platforms
    if rpm --quiet -q kernel-core; then

    if ! rpm -q --quiet "aide" ; then
        dnf install -y "aide"
    fi

    if grep -i -E '^.*(/usr)?/sbin/auditctl.*$' /etc/aide.conf; then
    sed -i -r "s#.*(/usr)?/sbin/auditctl.*#/usr/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512#" /etc/aide.conf
    else
    echo "/usr/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide.conf
    fi

    if grep -i -E '^.*(/usr)?/sbin/auditd.*$' /etc/aide.conf; then
    sed -i -r "s#.*(/usr)?/sbin/auditd.*#/usr/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512#" /etc/aide.conf
    else
    echo "/usr/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide.conf
    fi

    if grep -i -E '^.*(/usr)?/sbin/ausearch.*$' /etc/aide.conf; then
    sed -i -r "s#.*(/usr)?/sbin/ausearch.*#/usr/sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512#" /etc/aide.conf
    else
    echo "/usr/sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide.conf
    fi

    if grep -i -E '^.*(/usr)?/sbin/aureport.*$' /etc/aide.conf; then
    sed -i -r "s#.*(/usr)?/sbin/aureport.*#/usr/sbin/aureport p+i+n+u+g+s+b+acl+xattrs+sha512#" /etc/aide.conf
    else
    echo "/usr/sbin/aureport p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide.conf
    fi

    if grep -i -E '^.*(/usr)?/sbin/autrace.*$' /etc/aide.conf; then
    sed -i -r "s#.*(/usr)?/sbin/autrace.*#/usr/sbin/autrace p+i+n+u+g+s+b+acl+xattrs+sha512#" /etc/aide.conf
    else
    echo "/usr/sbin/autrace p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide.conf
    fi

    if grep -i -E '^.*(/usr)?/sbin/augenrules.*$' /etc/aide.conf; then
    sed -i -r "s#.*(/usr)?/sbin/augenrules.*#/usr/sbin/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512#" /etc/aide.conf
    else
    echo "/usr/sbin/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide.conf
    fi

    if grep -i -E '^.*(/usr)?/sbin/rsyslogd.*$' /etc/aide.conf; then
    sed -i -r "s#.*(/usr)?/sbin/rsyslogd.*#/usr/sbin/rsyslogd p+i+n+u+g+s+b+acl+xattrs+sha512#" /etc/aide.conf
    else
    echo "/usr/sbin/rsyslogd p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide.conf
    fi

    else
        >&2 echo 'Remediation is not applicable, nothing was done'
    fi

    # Remediation is applicable only in certain platforms
    if rpm --quiet -q kernel-core; then

    if ! rpm -q --quiet "aide" ; then
        dnf install -y "aide"
    fi

    if ! rpm -q --quiet "cronie" ; then
        dnf install -y "cronie"
    fi

    CRON_FILE="/etc/crontab"

    if ! grep -q "/usr/sbin/aide --check" "${CRON_FILE}" ; then
        echo "05 4 * * * root /usr/sbin/aide --check" >> "${CRON_FILE}"
    else
        sed -i '\!^.* --check.*$!d' "${CRON_FILE}"
        echo "05 4 * * * root /usr/sbin/aide --check" >> "${CRON_FILE}"
    fi

    else
        >&2 echo 'Remediation is not applicable, nothing was done'
    fi

    # ── aide --init : DÉCOMMENTER EN FENÊTRE DE MAINTENANCE ────────────────
    # # Remediation is applicable only in certain platforms
    # if rpm --quiet -q kernel-core; then
    #
    # if ! rpm -q --quiet "aide" ; then
    #     dnf install -y "aide"
    # fi
    #
    # /usr/sbin/aide --init
    # /bin/cp -p /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
    #
    # else
    #     >&2 echo 'Remediation is not applicable, nothing was done'
    # fi
    # ───────────────────────────────────────────────────────────────────────
    log_ok "AIDE installé et configuré (--init à exécuter manuellement)"
}

section_22() {
    echo "--- SECTION 22: Custom Crypto Policy CIS ---"
    log_info "Désactive CBC/weak ciphers/weak MACs pour SSH"
    if $DRY_RUN; then
        echo -e "${BLUE}[DRY-RUN]${NC} Créer modules NO-SSHCBC NO-SSHWEAKCIPHERS NO-SSHWEAKMACS NO-WEAKMAC"
        echo -e "${BLUE}[DRY-RUN]${NC} update-crypto-policies --set DEFAULT:NO-SHA1:NO-SSHCBC:NO-SSHWEAKCIPHERS:NO-SSHWEAKMACS:NO-WEAKMAC"
        return
    fi
    local poldir="/etc/crypto-policies/policies/modules"
    mkdir -p "$poldir"
    printf 'cipher@SSH = -*-CBC\n'                                                        > "${poldir}/NO-SSHCBC.pmod"
    printf 'cipher@SSH = -3DES-CBC -AES-128-CBC -AES-192-CBC -AES-256-CBC -CHACHA20-POLY1305\n' > "${poldir}/NO-SSHWEAKCIPHERS.pmod"
    printf 'mac@SSH = -HMAC-MD5* -UMAC-64* -UMAC-128*\n'                                 > "${poldir}/NO-SSHWEAKMACS.pmod"
    printf 'mac = -*-128*\n'                                                              > "${poldir}/NO-WEAKMAC.pmod"
    log_ok "Modules crypto créés"
    local expected="DEFAULT:NO-SHA1:NO-SSHCBC:NO-SSHWEAKCIPHERS:NO-SSHWEAKMACS:NO-WEAKMAC"
    local current; current=$(update-crypto-policies --show 2>/dev/null || echo "")
    if [[ "$current" != "$expected" ]]; then
        update-crypto-policies --set "$expected"
    fi
    log_ok "Crypto policy: ${expected}"
}

section_23() {
    echo "--- SECTION 23: Durcissement sudo ---"
    log_info "use_pty + timestamp_timeout=5"
    rpm --quiet -q sudo 2>/dev/null || { log_warn "sudo absent — ignoré"; return; }
    if $DRY_RUN; then
        echo -e "${BLUE}[DRY-RUN]${NC} sudoers: Defaults use_pty"
        echo -e "${BLUE}[DRY-RUN]${NC} sudoers: Defaults timestamp_timeout=5"
        return
    fi

    # Remediation is applicable only in certain platforms
    if rpm --quiet -q kernel-core && { rpm --quiet -q sudo; }; then

    if /usr/sbin/visudo -qcf /etc/sudoers; then
        cp /etc/sudoers /etc/sudoers.bak
        if ! grep -P '^[\s]*Defaults\b[^!\n]*\buse_pty.*$' /etc/sudoers; then
            # sudoers file doesn't define Option use_pty
            echo "Defaults use_pty" >> /etc/sudoers
        fi

        # Check validity of sudoers and cleanup bak
        if /usr/sbin/visudo -qcf /etc/sudoers; then
            rm -f /etc/sudoers.bak
        else
            echo "Fail to validate remediated /etc/sudoers, reverting to original file."
            mv /etc/sudoers.bak /etc/sudoers
            false
        fi
    else
        echo "Skipping remediation, /etc/sudoers failed to validate"
        false
    fi

    else
        >&2 echo 'Remediation is not applicable, nothing was done'
    fi

    # Remediation is applicable only in certain platforms
    if rpm --quiet -q kernel-core && { rpm --quiet -q sudo; }; then

    var_sudo_timestamp_timeout='5'

    if grep -Px '^[\s]*Defaults.*timestamp_timeout[\s]*=.*' /etc/sudoers.d/*; then
        find /etc/sudoers.d/ -type f -exec sed -Ei "/^[[:blank:]]*Defaults.*timestamp_timeout[[:blank:]]*=.*/d" {} \;
    fi

    if /usr/sbin/visudo -qcf /etc/sudoers; then
        cp /etc/sudoers /etc/sudoers.bak
        if ! grep -P '^[\s]*Defaults.*timestamp_timeout[\s]*=[\s]*[-]?\w+.*$' /etc/sudoers; then
            # sudoers file doesn't define Option timestamp_timeout
            echo "Defaults timestamp_timeout=${var_sudo_timestamp_timeout}" >> /etc/sudoers
        else
            # sudoers file defines Option timestamp_timeout, remediate wrong values if present
            if grep -qP "^[\s]*Defaults\s.*\btimestamp_timeout[\s]*=[\s]*(?!${var_sudo_timestamp_timeout}\b)[-]?\w+\b.*$" /etc/sudoers; then
                sed -Ei "s/(^[[:blank:]]*Defaults.*timestamp_timeout[[:blank:]]*=)[[:blank:]]*[-]?\w+(.*$)/\1${var_sudo_timestamp_timeout}\2/" /etc/sudoers
            fi
        fi

        # Check validity of sudoers and cleanup bak
        if /usr/sbin/visudo -qcf /etc/sudoers; then
            rm -f /etc/sudoers.bak
        else
            echo "Fail to validate remediated /etc/sudoers, reverting to original file."
            mv /etc/sudoers.bak /etc/sudoers
            false
        fi
    else
        echo "Skipping remediation, /etc/sudoers failed to validate"
        false
    fi

    else
        >&2 echo 'Remediation is not applicable, nothing was done'
    fi
    log_ok "sudo: use_pty + timestamp_timeout=5"
}

section_24() {
    echo "--- SECTION 24: PAM Faillock (verrouillage compte) ---"
    log_info "deny=5 tentatives, unlock_time=900s"
    log_info "Comptes LOCAUX uniquement — FreeIPA gère les siens via ipa pwpolicy"
    log_warn "Vérifier : authselect current (doit être sssd ou ipa)"
    if $DRY_RUN; then
        echo -e "${BLUE}[DRY-RUN]${NC} authselect enable-feature with-faillock"
        echo -e "${BLUE}[DRY-RUN]${NC} faillock.conf: deny=5 unlock_time=900"
        return
    fi

    # Remediation is applicable only in certain platforms
    if rpm --quiet -q kernel-core; then

    if [ -f /usr/bin/authselect ]; then
        if ! authselect check; then
    echo "
    authselect integrity check failed. Remediation aborted!
    This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
    It is not recommended to manually edit the PAM files when authselect tool is available.
    In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
    exit 1
    fi
    authselect enable-feature with-faillock

    authselect apply-changes -b
    else

    AUTH_FILES=("/etc/pam.d/system-auth" "/etc/pam.d/password-auth")
    for pam_file in "${AUTH_FILES[@]}"
    do
        if ! grep -qE '^\s*auth\s+required\s+pam_faillock\.so\s+(preauth silent|authfail).*$' "$pam_file" ; then
            sed -i --follow-symlinks '/^auth.*sufficient.*pam_unix\.so.*/i auth        required      pam_faillock.so preauth silent' "$pam_file"
            sed -i --follow-symlinks '/^auth.*required.*pam_deny\.so.*/i auth        required      pam_faillock.so authfail' "$pam_file"
            sed -i --follow-symlinks '/^account.*required.*pam_unix\.so.*/i account     required      pam_faillock.so' "$pam_file"
        fi
        sed -Ei 's/(auth.*)(\[default=die\])(.*pam_faillock\.so)/\1required     \3/g' "$pam_file"
    done

    fi

    else
        >&2 echo 'Remediation is not applicable, nothing was done'
    fi

    # Remediation is applicable only in certain platforms
    if rpm --quiet -q kernel-core && { rpm --quiet -q pam; }; then

    var_accounts_passwords_pam_faillock_deny='5'

    if [ -f /usr/bin/authselect ]; then
        if ! authselect check; then
    echo "
    authselect integrity check failed. Remediation aborted!
    This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
    It is not recommended to manually edit the PAM files when authselect tool is available.
    In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
    exit 1
    fi
    authselect enable-feature with-faillock

    authselect apply-changes -b
    else

    AUTH_FILES=("/etc/pam.d/system-auth" "/etc/pam.d/password-auth")
    for pam_file in "${AUTH_FILES[@]}"
    do
        if ! grep -qE '^\s*auth\s+required\s+pam_faillock\.so\s+(preauth silent|authfail).*$' "$pam_file" ; then
            sed -i --follow-symlinks '/^auth.*sufficient.*pam_unix\.so.*/i auth        required      pam_faillock.so preauth silent' "$pam_file"
            sed -i --follow-symlinks '/^auth.*required.*pam_deny\.so.*/i auth        required      pam_faillock.so authfail' "$pam_file"
            sed -i --follow-symlinks '/^account.*required.*pam_unix\.so.*/i account     required      pam_faillock.so' "$pam_file"
        fi
        sed -Ei 's/(auth.*)(\[default=die\])(.*pam_faillock\.so)/\1required     \3/g' "$pam_file"
    done

    fi

    AUTH_FILES=("/etc/pam.d/system-auth" "/etc/pam.d/password-auth")
    SKIP_FAILLOCK_CHECK=false

    FAILLOCK_CONF="/etc/security/faillock.conf"
    if [ -f $FAILLOCK_CONF ] || [ "$SKIP_FAILLOCK_CHECK" = "true" ]; then
        regex="^\s*deny\s*="
        line="deny = $var_accounts_passwords_pam_faillock_deny"
        if ! grep -q $regex $FAILLOCK_CONF; then
            echo $line >> $FAILLOCK_CONF
        else
            sed -i --follow-symlinks 's|^\s*\(deny\s*=\s*\)\(\S\+\)|\1'"$var_accounts_passwords_pam_faillock_deny"'|g' $FAILLOCK_CONF
        fi

        for pam_file in "${AUTH_FILES[@]}"
        do
            if [ -e "$pam_file" ] ; then
                PAM_FILE_PATH="$pam_file"
                if [ -f /usr/bin/authselect ]; then

                    if ! authselect check; then
                    echo "
                    authselect integrity check failed. Remediation aborted!
                    This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
                    It is not recommended to manually edit the PAM files when authselect tool is available.
                    In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
                    exit 1
                    fi

                    CURRENT_PROFILE=$(authselect current -r | awk '{ print $1 }')
                    # If not already in use, a custom profile is created preserving the enabled features.
                    if [[ ! $CURRENT_PROFILE == custom/* ]]; then
                        ENABLED_FEATURES=$(authselect current | tail -n+3 | awk '{ print $2 }')
                        # The "local" profile does not contain essential security features required by multiple Benchmarks.
                        # If currently used, it is replaced by "sssd", which is the best option in this case.
                        if [[ $CURRENT_PROFILE == local ]]; then
                            CURRENT_PROFILE="sssd"
                        fi
                        authselect create-profile hardening -b $CURRENT_PROFILE
                        CURRENT_PROFILE="custom/hardening"

                        authselect apply-changes -b --backup=before-hardening-custom-profile
                        authselect select $CURRENT_PROFILE
                        for feature in $ENABLED_FEATURES; do
                            authselect enable-feature $feature;
                        done

                        authselect apply-changes -b --backup=after-hardening-custom-profile
                    fi
                    PAM_FILE_NAME=$(basename "$pam_file")
                    PAM_FILE_PATH="/etc/authselect/$CURRENT_PROFILE/$PAM_FILE_NAME"

                    authselect apply-changes -b
                fi

            if grep -qP "^\s*auth\s.*\bpam_faillock.so\s.*\bdeny\b" "$PAM_FILE_PATH"; then
                sed -i -E --follow-symlinks "s/(.*auth.*pam_faillock.so.*)\bdeny\b=?[[:alnum:]]*(.*)/\1\2/g" "$PAM_FILE_PATH"
            fi
                if [ -f /usr/bin/authselect ]; then

                    authselect apply-changes -b
                fi
            else
                echo "$pam_file was not found" >&2
            fi
        done

    else
        for pam_file in "${AUTH_FILES[@]}"
        do
            if ! grep -qE '^\s*auth.*pam_faillock\.so\s+(preauth|authfail).*deny' "$pam_file"; then
                sed -i --follow-symlinks '/^auth.*required.*pam_faillock\.so.*preauth.*/ s/$/ deny='"$var_accounts_passwords_pam_faillock_deny"'/' "$pam_file"
                sed -i --follow-symlinks '/^auth.*required.*pam_faillock\.so.*authfail.*/ s/$/ deny='"$var_accounts_passwords_pam_faillock_deny"'/' "$pam_file"
            else
                sed -i --follow-symlinks 's/\(^auth.*required.*pam_faillock\.so.*preauth.*\)\('"deny"'=\)\S\+\b\(.*\)/\1\2'"$var_accounts_passwords_pam_faillock_deny"'\3/' "$pam_file"
                sed -i --follow-symlinks 's/\(^auth.*required.*pam_faillock\.so.*authfail.*\)\('"deny"'=\)\S\+\b\(.*\)/\1\2'"$var_accounts_passwords_pam_faillock_deny"'\3/' "$pam_file"
            fi
        done
    fi

    else
        >&2 echo 'Remediation is not applicable, nothing was done'
    fi

    # Remediation is applicable only in certain platforms
    if rpm --quiet -q kernel-core && { rpm --quiet -q pam; }; then

    var_accounts_passwords_pam_faillock_unlock_time='900'

    if [ -f /usr/bin/authselect ]; then
        if ! authselect check; then
    echo "
    authselect integrity check failed. Remediation aborted!
    This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
    It is not recommended to manually edit the PAM files when authselect tool is available.
    In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
    exit 1
    fi
    authselect enable-feature with-faillock

    authselect apply-changes -b
    else

    AUTH_FILES=("/etc/pam.d/system-auth" "/etc/pam.d/password-auth")
    for pam_file in "${AUTH_FILES[@]}"
    do
        if ! grep -qE '^\s*auth\s+required\s+pam_faillock\.so\s+(preauth silent|authfail).*$' "$pam_file" ; then
            sed -i --follow-symlinks '/^auth.*sufficient.*pam_unix\.so.*/i auth        required      pam_faillock.so preauth silent' "$pam_file"
            sed -i --follow-symlinks '/^auth.*required.*pam_deny\.so.*/i auth        required      pam_faillock.so authfail' "$pam_file"
            sed -i --follow-symlinks '/^account.*required.*pam_unix\.so.*/i account     required      pam_faillock.so' "$pam_file"
        fi
        sed -Ei 's/(auth.*)(\[default=die\])(.*pam_faillock\.so)/\1required     \3/g' "$pam_file"
    done

    fi

    AUTH_FILES=("/etc/pam.d/system-auth" "/etc/pam.d/password-auth")
    SKIP_FAILLOCK_CHECK=false

    FAILLOCK_CONF="/etc/security/faillock.conf"
    if [ -f $FAILLOCK_CONF ] || [ "$SKIP_FAILLOCK_CHECK" = "true" ]; then
        regex="^\s*unlock_time\s*="
        line="unlock_time = $var_accounts_passwords_pam_faillock_unlock_time"
        if ! grep -q $regex $FAILLOCK_CONF; then
            echo $line >> $FAILLOCK_CONF
        else
            sed -i --follow-symlinks 's|^\s*\(unlock_time\s*=\s*\)\(\S\+\)|\1'"$var_accounts_passwords_pam_faillock_unlock_time"'|g' $FAILLOCK_CONF
        fi

        for pam_file in "${AUTH_FILES[@]}"
        do
            if [ -e "$pam_file" ] ; then
                PAM_FILE_PATH="$pam_file"
                if [ -f /usr/bin/authselect ]; then

                    if ! authselect check; then
                    echo "
                    authselect integrity check failed. Remediation aborted!
                    This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
                    It is not recommended to manually edit the PAM files when authselect tool is available.
                    In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
                    exit 1
                    fi

                    CURRENT_PROFILE=$(authselect current -r | awk '{ print $1 }')
                    # If not already in use, a custom profile is created preserving the enabled features.
                    if [[ ! $CURRENT_PROFILE == custom/* ]]; then
                        ENABLED_FEATURES=$(authselect current | tail -n+3 | awk '{ print $2 }')
                        # The "local" profile does not contain essential security features required by multiple Benchmarks.
                        # If currently used, it is replaced by "sssd", which is the best option in this case.
                        if [[ $CURRENT_PROFILE == local ]]; then
                            CURRENT_PROFILE="sssd"
                        fi
                        authselect create-profile hardening -b $CURRENT_PROFILE
                        CURRENT_PROFILE="custom/hardening"

                        authselect apply-changes -b --backup=before-hardening-custom-profile
                        authselect select $CURRENT_PROFILE
                        for feature in $ENABLED_FEATURES; do
                            authselect enable-feature $feature;
                        done

                        authselect apply-changes -b --backup=after-hardening-custom-profile
                    fi
                    PAM_FILE_NAME=$(basename "$pam_file")
                    PAM_FILE_PATH="/etc/authselect/$CURRENT_PROFILE/$PAM_FILE_NAME"

                    authselect apply-changes -b
                fi

            if grep -qP "^\s*auth\s.*\bpam_faillock.so\s.*\bunlock_time\b" "$PAM_FILE_PATH"; then
                sed -i -E --follow-symlinks "s/(.*auth.*pam_faillock.so.*)\bunlock_time\b=?[[:alnum:]]*(.*)/\1\2/g" "$PAM_FILE_PATH"
            fi
                if [ -f /usr/bin/authselect ]; then

                    authselect apply-changes -b
                fi
            else
                echo "$pam_file was not found" >&2
            fi
        done

    else
        for pam_file in "${AUTH_FILES[@]}"
        do
            if ! grep -qE '^\s*auth.*pam_faillock\.so\s+(preauth|authfail).*unlock_time' "$pam_file"; then
                sed -i --follow-symlinks '/^auth.*required.*pam_faillock\.so.*preauth.*/ s/$/ unlock_time='"$var_accounts_passwords_pam_faillock_unlock_time"'/' "$pam_file"
                sed -i --follow-symlinks '/^auth.*required.*pam_faillock\.so.*authfail.*/ s/$/ unlock_time='"$var_accounts_passwords_pam_faillock_unlock_time"'/' "$pam_file"
            else
                sed -i --follow-symlinks 's/\(^auth.*required.*pam_faillock\.so.*preauth.*\)\('"unlock_time"'=\)\S\+\b\(.*\)/\1\2'"$var_accounts_passwords_pam_faillock_unlock_time"'\3/' "$pam_file"
                sed -i --follow-symlinks 's/\(^auth.*required.*pam_faillock\.so.*authfail.*\)\('"unlock_time"'=\)\S\+\b\(.*\)/\1\2'"$var_accounts_passwords_pam_faillock_unlock_time"'\3/' "$pam_file"
            fi
        done
    fi

    else
        >&2 echo 'Remediation is not applicable, nothing was done'
    fi
    log_ok "pam_faillock: deny=5, unlock_time=900"
}

section_25() {
    echo "--- SECTION 25: PAM pwquality (qualité mots de passe) ---"
    log_info "minlen=14  difok=2  minclass=4  maxsequence=3  dictcheck=1  enforce_for_root"
    log_info "Comptes LOCAUX — pour FreeIPA: ipa pwpolicy-mod"
    if $DRY_RUN; then
        echo -e "${BLUE}[DRY-RUN]${NC} pwquality.conf: minlen=14 difok=2 minclass=4 maxsequence=3 dictcheck=1 enforce_for_root"
        return
    fi

    # Remediation is applicable only in certain platforms
    if rpm --quiet -q kernel-core && { rpm --quiet -q libpwquality; }; then

    var_password_pam_minlen='14'

    if grep -sq minlen /etc/security/pwquality.conf.d/*.conf ; then
        sed -i "/minlen/d" /etc/security/pwquality.conf.d/*.conf
    fi

    # Strip any search characters in the key arg so that the key can be replaced without
    # adding any search characters to the config file.
    stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^minlen")

    # shellcheck disable=SC2059
    printf -v formatted_output "%s = %s" "$stripped_key" "$var_password_pam_minlen"

    # If the key exists, change it. Otherwise, add it to the config_file.
    # We search for the key string followed by a word boundary (matched by \>),
    # so if we search for 'setting', 'setting2' won't match.
    if LC_ALL=C grep -q -m 1 -i -e "^minlen\\>" "/etc/security/pwquality.conf"; then
        escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
        LC_ALL=C sed -i --follow-symlinks "s/^minlen\\>.*/$escaped_formatted_output/gi" "/etc/security/pwquality.conf"
    else
        if [[ -s "/etc/security/pwquality.conf" ]] && [[ -n "$(tail -c 1 -- "/etc/security/pwquality.conf" || true)" ]]; then
            LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/security/pwquality.conf"
        fi
        cce="CCE-83579-3"
        printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "/etc/security/pwquality.conf" >> "/etc/security/pwquality.conf"
        printf '%s\n' "$formatted_output" >> "/etc/security/pwquality.conf"
    fi

    else
        >&2 echo 'Remediation is not applicable, nothing was done'
    fi

    # Remediation is applicable only in certain platforms
    if rpm --quiet -q kernel-core && { rpm --quiet -q libpwquality; }; then

    var_password_pam_difok='2'

    if grep -sq difok /etc/security/pwquality.conf.d/*.conf ; then
        sed -i "/difok/d" /etc/security/pwquality.conf.d/*.conf
    fi

    # Strip any search characters in the key arg so that the key can be replaced without
    # adding any search characters to the config file.
    stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^difok")

    # shellcheck disable=SC2059
    printf -v formatted_output "%s = %s" "$stripped_key" "$var_password_pam_difok"

    # If the key exists, change it. Otherwise, add it to the config_file.
    # We search for the key string followed by a word boundary (matched by \>),
    # so if we search for 'setting', 'setting2' won't match.
    if LC_ALL=C grep -q -m 1 -i -e "^difok\\>" "/etc/security/pwquality.conf"; then
        escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
        LC_ALL=C sed -i --follow-symlinks "s/^difok\\>.*/$escaped_formatted_output/gi" "/etc/security/pwquality.conf"
    else
        if [[ -s "/etc/security/pwquality.conf" ]] && [[ -n "$(tail -c 1 -- "/etc/security/pwquality.conf" || true)" ]]; then
            LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/security/pwquality.conf"
        fi
        cce="CCE-83564-5"
        printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "/etc/security/pwquality.conf" >> "/etc/security/pwquality.conf"
        printf '%s\n' "$formatted_output" >> "/etc/security/pwquality.conf"
    fi

    else
        >&2 echo 'Remediation is not applicable, nothing was done'
    fi

    # Remediation is applicable only in certain platforms
    if rpm --quiet -q kernel-core && { rpm --quiet -q libpwquality; }; then

    var_password_pam_minclass='4'

    if grep -sq minclass /etc/security/pwquality.conf.d/*.conf ; then
        sed -i "/minclass/d" /etc/security/pwquality.conf.d/*.conf
    fi

    # Strip any search characters in the key arg so that the key can be replaced without
    # adding any search characters to the config file.
    stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^minclass")

    # shellcheck disable=SC2059
    printf -v formatted_output "%s = %s" "$stripped_key" "$var_password_pam_minclass"

    # If the key exists, change it. Otherwise, add it to the config_file.
    # We search for the key string followed by a word boundary (matched by \>),
    # so if we search for 'setting', 'setting2' won't match.
    if LC_ALL=C grep -q -m 1 -i -e "^minclass\\>" "/etc/security/pwquality.conf"; then
        escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
        LC_ALL=C sed -i --follow-symlinks "s/^minclass\\>.*/$escaped_formatted_output/gi" "/etc/security/pwquality.conf"
    else
        if [[ -s "/etc/security/pwquality.conf" ]] && [[ -n "$(tail -c 1 -- "/etc/security/pwquality.conf" || true)" ]]; then
            LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/security/pwquality.conf"
        fi
        cce="CCE-83563-7"
        printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "/etc/security/pwquality.conf" >> "/etc/security/pwquality.conf"
        printf '%s\n' "$formatted_output" >> "/etc/security/pwquality.conf"
    fi

    else
        >&2 echo 'Remediation is not applicable, nothing was done'
    fi

    # Remediation is applicable only in certain platforms
    if rpm --quiet -q kernel-core && { rpm --quiet -q libpwquality; }; then

    var_password_pam_maxsequence='3'

    if grep -sq maxsequence /etc/security/pwquality.conf.d/*.conf ; then
        sed -i "/maxsequence/d" /etc/security/pwquality.conf.d/*.conf
    fi

    # Strip any search characters in the key arg so that the key can be replaced without
    # adding any search characters to the config file.
    stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^maxsequence")

    # shellcheck disable=SC2059
    printf -v formatted_output "%s = %s" "$stripped_key" "$var_password_pam_maxsequence"

    # If the key exists, change it. Otherwise, add it to the config_file.
    # We search for the key string followed by a word boundary (matched by \>),
    # so if we search for 'setting', 'setting2' won't match.
    if LC_ALL=C grep -q -m 1 -i -e "^maxsequence\\>" "/etc/security/pwquality.conf"; then
        escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
        LC_ALL=C sed -i --follow-symlinks "s/^maxsequence\\>.*/$escaped_formatted_output/gi" "/etc/security/pwquality.conf"
    else
        if [[ -s "/etc/security/pwquality.conf" ]] && [[ -n "$(tail -c 1 -- "/etc/security/pwquality.conf" || true)" ]]; then
            LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/security/pwquality.conf"
        fi
        cce="CCE-86444-7"
        printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "/etc/security/pwquality.conf" >> "/etc/security/pwquality.conf"
        printf '%s\n' "$formatted_output" >> "/etc/security/pwquality.conf"
    fi

    else
        >&2 echo 'Remediation is not applicable, nothing was done'
    fi

    # Remediation is applicable only in certain platforms
    if rpm --quiet -q kernel-core && { rpm --quiet -q libpwquality; }; then

    var_password_pam_dictcheck='1'

    if grep -sq dictcheck /etc/security/pwquality.conf.d/*.conf ; then
        sed -i "/dictcheck/d" /etc/security/pwquality.conf.d/*.conf
    fi

    # Strip any search characters in the key arg so that the key can be replaced without
    # adding any search characters to the config file.
    stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^dictcheck")

    # shellcheck disable=SC2059
    printf -v formatted_output "%s = %s" "$stripped_key" "$var_password_pam_dictcheck"

    # If the key exists, change it. Otherwise, add it to the config_file.
    # We search for the key string followed by a word boundary (matched by \>),
    # so if we search for 'setting', 'setting2' won't match.
    if LC_ALL=C grep -q -m 1 -i -e "^dictcheck\\>" "/etc/security/pwquality.conf"; then
        escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
        LC_ALL=C sed -i --follow-symlinks "s/^dictcheck\\>.*/$escaped_formatted_output/gi" "/etc/security/pwquality.conf"
    else
        if [[ -s "/etc/security/pwquality.conf" ]] && [[ -n "$(tail -c 1 -- "/etc/security/pwquality.conf" || true)" ]]; then
            LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/security/pwquality.conf"
        fi
        cce="CCE-88413-0"
        printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "/etc/security/pwquality.conf" >> "/etc/security/pwquality.conf"
        printf '%s\n' "$formatted_output" >> "/etc/security/pwquality.conf"
    fi

    else
        >&2 echo 'Remediation is not applicable, nothing was done'
    fi

    # Remediation is applicable only in certain platforms
    if rpm --quiet -q kernel-core && { rpm --quiet -q libpwquality; }; then

    if [ -e "/etc/security/pwquality.conf" ] ; then

        LC_ALL=C sed -i "/^\s*enforce_for_root/Id" "/etc/security/pwquality.conf"
    else
        touch "/etc/security/pwquality.conf"
    fi
    # make sure file has newline at the end
    sed -i -e '$a\' "/etc/security/pwquality.conf"

    cp "/etc/security/pwquality.conf" "/etc/security/pwquality.conf.bak"
    # Insert at the end of the file
    printf '%s\n' "enforce_for_root" >> "/etc/security/pwquality.conf"
    # Clean up after ourselves.
    rm "/etc/security/pwquality.conf.bak"

    else
        >&2 echo 'Remediation is not applicable, nothing was done'
    fi
    log_ok "pwquality configuré"
}

section_26() {
    echo "--- SECTION 26: Historique mots de passe (remember=24) ---"
    log_info "Empêche réutilisation des 24 derniers MDP — comptes LOCAUX"
    log_info "FreeIPA: ipa pwpolicy-mod --history=24"
    if $DRY_RUN; then
        echo -e "${BLUE}[DRY-RUN]${NC} authselect enable-feature with-pwhistory (remember=24)"
        return
    fi

    # Remediation is applicable only in certain platforms
    if rpm --quiet -q kernel-core && { rpm --quiet -q pam; }; then

    var_password_pam_remember='24'
    var_password_pam_remember_control_flag='requisite,required'

    var_password_pam_remember_control_flag="$(echo $var_password_pam_remember_control_flag | cut -d \, -f 1)"

    if [ -f /usr/bin/authselect ]; then
        if authselect list-features sssd | grep -q with-pwhistory; then
            if ! authselect check; then
            echo "
            authselect integrity check failed. Remediation aborted!
            This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
            It is not recommended to manually edit the PAM files when authselect tool is available.
            In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
            exit 1
            fi
            authselect enable-feature with-pwhistory

            authselect apply-changes -b
        else

            if ! authselect check; then
            echo "
            authselect integrity check failed. Remediation aborted!
            This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
            It is not recommended to manually edit the PAM files when authselect tool is available.
            In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
            exit 1
            fi

            CURRENT_PROFILE=$(authselect current -r | awk '{ print $1 }')
            # If not already in use, a custom profile is created preserving the enabled features.
            if [[ ! $CURRENT_PROFILE == custom/* ]]; then
                ENABLED_FEATURES=$(authselect current | tail -n+3 | awk '{ print $2 }')
                # The "local" profile does not contain essential security features required by multiple Benchmarks.
                # If currently used, it is replaced by "sssd", which is the best option in this case.
                if [[ $CURRENT_PROFILE == local ]]; then
                    CURRENT_PROFILE="sssd"
                fi
                authselect create-profile hardening -b $CURRENT_PROFILE
                CURRENT_PROFILE="custom/hardening"

                authselect apply-changes -b --backup=before-hardening-custom-profile
                authselect select $CURRENT_PROFILE
                for feature in $ENABLED_FEATURES; do
                    authselect enable-feature $feature;
                done

                authselect apply-changes -b --backup=after-hardening-custom-profile
            fi
            PAM_FILE_NAME=$(basename "/etc/pam.d/password-auth")
            PAM_FILE_PATH="/etc/authselect/$CURRENT_PROFILE/$PAM_FILE_NAME"

            authselect apply-changes -b

            if ! grep -qP "^\s*password\s+\$var_password_pam_remember_control_flag\s+pam_pwhistory.so\s*.*" "$PAM_FILE_PATH"; then
                # Line matching group + control + module was not found. Check group + module.
                if [ "$(grep -cP '^\s*password\s+.*\s+pam_pwhistory.so\s*' "$PAM_FILE_PATH")" -eq 1 ]; then
                    # The control is updated only if one single line matches.
                    sed -i -E --follow-symlinks "s/^(\s*password\s+).*(\bpam_pwhistory.so.*)/\1$var_password_pam_remember_control_flag \2/" "$PAM_FILE_PATH"
                else
                    LAST_MATCH_LINE=$(grep -nP "^password.*requisite.*pam_pwquality\.so" "$PAM_FILE_PATH" | tail -n 1 | cut -d: -f 1)
                    if [ ! -z $LAST_MATCH_LINE ]; then
                        sed -i --follow-symlinks $LAST_MATCH_LINE" a password     $var_password_pam_remember_control_flag    pam_pwhistory.so" "$PAM_FILE_PATH"
                    else
                        echo "password    $var_password_pam_remember_control_flag    pam_pwhistory.so" >> "$PAM_FILE_PATH"
                    fi
                fi
            fi
        fi
    else


        if ! grep -qP "^\s*password\s+\$var_password_pam_remember_control_flag\s+pam_pwhistory.so\s*.*" "/etc/pam.d/password-auth"; then
            # Line matching group + control + module was not found. Check group + module.
            if [ "$(grep -cP '^\s*password\s+.*\s+pam_pwhistory.so\s*' "/etc/pam.d/password-auth")" -eq 1 ]; then
                # The control is updated only if one single line matches.
                sed -i -E --follow-symlinks "s/^(\s*password\s+).*(\bpam_pwhistory.so.*)/\1$var_password_pam_remember_control_flag \2/" "/etc/pam.d/password-auth"
            else
                LAST_MATCH_LINE=$(grep -nP "^password.*requisite.*pam_pwquality\.so" "/etc/pam.d/password-auth" | tail -n 1 | cut -d: -f 1)
                if [ ! -z $LAST_MATCH_LINE ]; then
                    sed -i --follow-symlinks $LAST_MATCH_LINE" a password     $var_password_pam_remember_control_flag    pam_pwhistory.so" "/etc/pam.d/password-auth"
                else
                    echo "password    $var_password_pam_remember_control_flag    pam_pwhistory.so" >> "/etc/pam.d/password-auth"
                fi
            fi
        fi

    fi

    PWHISTORY_CONF="/etc/security/pwhistory.conf"
    if [ -f $PWHISTORY_CONF ]; then
        regex="^\s*remember\s*="
        line="remember = $var_password_pam_remember"
        if ! grep -q $regex $PWHISTORY_CONF; then
            echo $line >> $PWHISTORY_CONF
        else
            sed -i --follow-symlinks 's|^\s*\(remember\s*=\s*\)\(\S\+\)|\1'"$var_password_pam_remember"'|g' $PWHISTORY_CONF
        fi
        if [ -e "/etc/pam.d/password-auth" ] ; then
            PAM_FILE_PATH="/etc/pam.d/password-auth"
            if [ -f /usr/bin/authselect ]; then

                if ! authselect check; then
                echo "
                authselect integrity check failed. Remediation aborted!
                This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
                It is not recommended to manually edit the PAM files when authselect tool is available.
                In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
                exit 1
                fi

                CURRENT_PROFILE=$(authselect current -r | awk '{ print $1 }')
                # If not already in use, a custom profile is created preserving the enabled features.
                if [[ ! $CURRENT_PROFILE == custom/* ]]; then
                    ENABLED_FEATURES=$(authselect current | tail -n+3 | awk '{ print $2 }')
                    # The "local" profile does not contain essential security features required by multiple Benchmarks.
                    # If currently used, it is replaced by "sssd", which is the best option in this case.
                    if [[ $CURRENT_PROFILE == local ]]; then
                        CURRENT_PROFILE="sssd"
                    fi
                    authselect create-profile hardening -b $CURRENT_PROFILE
                    CURRENT_PROFILE="custom/hardening"

                    authselect apply-changes -b --backup=before-hardening-custom-profile
                    authselect select $CURRENT_PROFILE
                    for feature in $ENABLED_FEATURES; do
                        authselect enable-feature $feature;
                    done

                    authselect apply-changes -b --backup=after-hardening-custom-profile
                fi
                PAM_FILE_NAME=$(basename "/etc/pam.d/password-auth")
                PAM_FILE_PATH="/etc/authselect/$CURRENT_PROFILE/$PAM_FILE_NAME"

                authselect apply-changes -b
            fi

        if grep -qP "^\s*password\s.*\bpam_pwhistory.so\s.*\bremember\b" "$PAM_FILE_PATH"; then
            sed -i -E --follow-symlinks "s/(.*password.*pam_pwhistory.so.*)\bremember\b=?[[:alnum:]]*(.*)/\1\2/g" "$PAM_FILE_PATH"
        fi
            if [ -f /usr/bin/authselect ]; then

                authselect apply-changes -b
            fi
        else
            echo "/etc/pam.d/password-auth was not found" >&2
        fi
    else
        PAM_FILE_PATH="/etc/pam.d/password-auth"
        if [ -f /usr/bin/authselect ]; then

            if ! authselect check; then
            echo "
            authselect integrity check failed. Remediation aborted!
            This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
            It is not recommended to manually edit the PAM files when authselect tool is available.
            In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
            exit 1
            fi

            CURRENT_PROFILE=$(authselect current -r | awk '{ print $1 }')
            # If not already in use, a custom profile is created preserving the enabled features.
            if [[ ! $CURRENT_PROFILE == custom/* ]]; then
                ENABLED_FEATURES=$(authselect current | tail -n+3 | awk '{ print $2 }')
                # The "local" profile does not contain essential security features required by multiple Benchmarks.
                # If currently used, it is replaced by "sssd", which is the best option in this case.
                if [[ $CURRENT_PROFILE == local ]]; then
                    CURRENT_PROFILE="sssd"
                fi
                authselect create-profile hardening -b $CURRENT_PROFILE
                CURRENT_PROFILE="custom/hardening"

                authselect apply-changes -b --backup=before-hardening-custom-profile
                authselect select $CURRENT_PROFILE
                for feature in $ENABLED_FEATURES; do
                    authselect enable-feature $feature;
                done

                authselect apply-changes -b --backup=after-hardening-custom-profile
            fi
            PAM_FILE_NAME=$(basename "/etc/pam.d/password-auth")
            PAM_FILE_PATH="/etc/authselect/$CURRENT_PROFILE/$PAM_FILE_NAME"

            authselect apply-changes -b
        fi


        if ! grep -qP "^\s*password\s+requisite\s+pam_pwhistory.so\s*.*" "$PAM_FILE_PATH"; then
            # Line matching group + control + module was not found. Check group + module.
            if [ "$(grep -cP '^\s*password\s+.*\s+pam_pwhistory.so\s*' "$PAM_FILE_PATH")" -eq 1 ]; then
                # The control is updated only if one single line matches.
                sed -i -E --follow-symlinks "s/^(\s*password\s+).*(\bpam_pwhistory.so.*)/\1requisite \2/" "$PAM_FILE_PATH"
            else
                echo "password    requisite    pam_pwhistory.so" >> "$PAM_FILE_PATH"
            fi
        fi
        # Check the option
        if ! grep -qP "^\s*password\s+requisite\s+pam_pwhistory.so\s*.*\sremember\b" "$PAM_FILE_PATH"; then
            sed -i -E --follow-symlinks "/\s*password\s+requisite\s+pam_pwhistory.so.*/ s/$/ remember=$var_password_pam_remember/" "$PAM_FILE_PATH"
        else
            sed -i -E --follow-symlinks "s/(\s*password\s+requisite\s+pam_pwhistory.so\s+.*)(remember=)[[:alnum:]]*\s*(.*)/\1\2$var_password_pam_remember \3/" "$PAM_FILE_PATH"
        fi
        if [ -f /usr/bin/authselect ]; then

            authselect apply-changes -b
        fi
    fi

    else
        >&2 echo 'Remediation is not applicable, nothing was done'
    fi
    log_ok "Historique MDP: remember=24"
}

section_27() {
    echo "--- SECTION 27: Politiques d'expiration de compte ---"
    log_info "PASS_MAX_DAYS=365  INACTIVE=45"
    log_warn "chage loop : vérifier comptes de service (awk -F: '/^[^:]+:[^!*]/{print \$1}' /etc/shadow)"
    if $DRY_RUN; then
        echo -e "${BLUE}[DRY-RUN]${NC} login.defs: PASS_MAX_DAYS=365"
        echo -e "${BLUE}[DRY-RUN]${NC} useradd: INACTIVE=45"
        echo -e "${BLUE}[DRY-RUN]${NC} chage -M 365 <comptes avec hash>"
        return
    fi

    # Remediation is applicable only in certain platforms
    if rpm --quiet -q kernel-core && { rpm --quiet -q shadow-utils; }; then

    var_accounts_maximum_age_login_defs='365'

    # Strip any search characters in the key arg so that the key can be replaced without
    # adding any search characters to the config file.
    stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^PASS_MAX_DAYS")

    # shellcheck disable=SC2059
    printf -v formatted_output "%s %s" "$stripped_key" "$var_accounts_maximum_age_login_defs"

    # If the key exists, change it. Otherwise, add it to the config_file.
    # We search for the key string followed by a word boundary (matched by \>),
    # so if we search for 'setting', 'setting2' won't match.
    if LC_ALL=C grep -q -m 1 -i -e "^PASS_MAX_DAYS\\>" "/etc/login.defs"; then
        escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
        LC_ALL=C sed -i --follow-symlinks "s/^PASS_MAX_DAYS\\>.*/$escaped_formatted_output/gi" "/etc/login.defs"
    else
        if [[ -s "/etc/login.defs" ]] && [[ -n "$(tail -c 1 -- "/etc/login.defs" || true)" ]]; then
            LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/login.defs"
        fi
        cce="CCE-83606-4"
        printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "/etc/login.defs" >> "/etc/login.defs"
        printf '%s\n' "$formatted_output" >> "/etc/login.defs"
    fi

    else
        >&2 echo 'Remediation is not applicable, nothing was done'
    fi

    # Remediation is applicable only in certain platforms
    if rpm --quiet -q kernel-core && { rpm --quiet -q shadow-utils; }; then

    var_account_disable_post_pw_expiration='45'

    # Strip any search characters in the key arg so that the key can be replaced without
    # adding any search characters to the config file.
    stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^INACTIVE")

    # shellcheck disable=SC2059
    printf -v formatted_output "%s=%s" "$stripped_key" "$var_account_disable_post_pw_expiration"

    # If the key exists, change it. Otherwise, add it to the config_file.
    # We search for the key string followed by a word boundary (matched by \>),
    # so if we search for 'setting', 'setting2' won't match.
    if LC_ALL=C grep -q -m 1 -i -e "^INACTIVE\\>" "/etc/default/useradd"; then
        escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
        LC_ALL=C sed -i --follow-symlinks "s/^INACTIVE\\>.*/$escaped_formatted_output/gi" "/etc/default/useradd"
    else
        if [[ -s "/etc/default/useradd" ]] && [[ -n "$(tail -c 1 -- "/etc/default/useradd" || true)" ]]; then
            LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/default/useradd"
        fi
        cce="CCE-83627-0"
        printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "/etc/default/useradd" >> "/etc/default/useradd"
        printf '%s\n' "$formatted_output" >> "/etc/default/useradd"
    fi

    else
        >&2 echo 'Remediation is not applicable, nothing was done'
    fi

    # Remediation is applicable only in certain platforms
    if rpm --quiet -q kernel-core; then

    var_accounts_maximum_age_login_defs='365'

    while IFS= read -r i; do

        chage -M $var_accounts_maximum_age_login_defs $i

    done <   <(awk -v var="$var_accounts_maximum_age_login_defs" -F: '(/^[^:]+:[^!*]/ && ($5 > var || $5 == "")) {print $1}' /etc/shadow)

    else
        >&2 echo 'Remediation is not applicable, nothing was done'
    fi
    log_ok "Expiration: PASS_MAX_DAYS=365 INACTIVE=45 appliqués"
}

section_28() {
    echo "--- SECTION 28: Restriction commande su (pam_wheel + sugroup) ---"
    log_warn "sugroup créé VIDE → su bloqué pour tout le monde"
    log_warn "Ajouter admins AVANT si besoin : gpasswd -a <user> sugroup"
    log_info "Compatible FreeIPA: admins utilisent sudo via sudorules IPA"
    if $DRY_RUN; then
        echo -e "${BLUE}[DRY-RUN]${NC} groupadd sugroup (vide)"
        echo -e "${BLUE}[DRY-RUN]${NC} /etc/pam.d/su: pam_wheel.so use_uid group=sugroup"
        return
    fi

    # Remediation is applicable only in certain platforms
    if rpm --quiet -q kernel-core; then

    var_pam_wheel_group_for_su='sugroup'

    # Workaround for https://github.com/OpenSCAP/openscap/issues/2242: Use full
    # path to groupadd command to avoid the issue with the command not being found.
    if ! grep -q "^${var_pam_wheel_group_for_su}:[^:]*:[^:]*:[^:]*" /etc/group; then
        /usr/sbin/groupadd ${var_pam_wheel_group_for_su}
    fi

    # group must be empty
    gpasswd -M '' ${var_pam_wheel_group_for_su}

    else
        >&2 echo 'Remediation is not applicable, nothing was done'
    fi

    # Remediation is applicable only in certain platforms
    if rpm --quiet -q pam; then

    var_pam_wheel_group_for_su='sugroup'

    PAM_CONF=/etc/pam.d/su

    pamstr=$(grep -P '^auth\s+required\s+pam_wheel\.so\s+(?=[^#]*\buse_uid\b)(?=[^#]*\bgroup=)' ${PAM_CONF})
    if [ -z "$pamstr" ]; then
        sed -Ei '/^auth\b.*\brequired\b.*\bpam_wheel\.so/d' ${PAM_CONF} # remove any remaining uncommented pam_wheel.so line
        sed -Ei "/^auth\s+sufficient\s+pam_rootok\.so.*$/a auth             required        pam_wheel.so use_uid group=${var_pam_wheel_group_for_su}" ${PAM_CONF}
    else
        group_val=$(echo -n "$pamstr" | grep -Eo '\bgroup=[_a-z][-0-9_a-z]*' | cut -d '=' -f 2)
        if [ -z "${group_val}" ] || [ ${group_val} != ${var_pam_wheel_group_for_su} ]; then
            sed -Ei "s/(^auth\s+required\s+pam_wheel.so\s+[^#]*group=)[_a-z][-0-9_a-z]*/\1${var_pam_wheel_group_for_su}/" ${PAM_CONF}
        fi
    fi

    else
        >&2 echo 'Remediation is not applicable, nothing was done'
    fi
    log_ok "su restreint au groupe sugroup"
}

section_29() {
    echo "--- SECTION 29: Journalisation persistante ---"
    log_info "systemd-journal-remote (optionnel si rsyslog → SIEM) + Storage=persistent"
    log_info "Complémentaire à rsyslog : journalctl --boot -1 nécessite Storage=persistent"
    if $DRY_RUN; then
        echo -e "${BLUE}[DRY-RUN]${NC} dnf install systemd-journal-remote"
        echo -e "${BLUE}[DRY-RUN]${NC} journald.conf: Storage=persistent"
        return
    fi

    # Remediation is applicable only in certain platforms
    if rpm --quiet -q kernel-core; then

    if ! rpm -q --quiet "systemd-journal-remote" ; then
        dnf install -y "systemd-journal-remote"
    fi

    else
        >&2 echo 'Remediation is not applicable, nothing was done'
    fi

    # Remediation is applicable only in certain platforms
    if rpm --quiet -q kernel-core; then

    found=false

    # set value in all files if they contain section or key
    for f in $(echo -n "/etc/systemd/journald.conf.d/complianceascode_hardening.conf /etc/systemd/journald.conf.d/*.conf /etc/systemd/journald.conf"); do
        if [ ! -e "$f" ]; then
            continue
        fi

        # find key in section and change value
        if grep -qzosP "[[:space:]]*\[Journal\]([^\n\[]*\n+)+?[[:space:]]*Storage" "$f"; then
            if ! grep -qPz "Storage=persistent" "$f"; then

                sed -i "s/Storage[^(\n)]*/Storage=persistent/" "$f"

            fi

            found=true

        # find section and add key = value to it
        elif grep -qs "[[:space:]]*\[Journal\]" "$f"; then

                sed -i "/[[:space:]]*\[Journal\]/a Storage=persistent" "$f"

                found=true
        fi
    done

    # if section not in any file, append section with key = value to FIRST file in files parameter
    if ! $found ; then
        file=$(echo "/etc/systemd/journald.conf.d/complianceascode_hardening.conf /etc/systemd/journald.conf.d/*.conf /etc/systemd/journald.conf" | cut -f1 -d ' ')
        mkdir -p "$(dirname "$file")"

        echo -e "[Journal]\nStorage=persistent" >> "$file"

    fi

    else
        >&2 echo 'Remediation is not applicable, nothing was done'
    fi
    log_ok "journald: Storage=persistent"
}


# ============================================================
# DISPATCHER
# ============================================================

echo "============================================================"
echo "  patch_cis.sh — CIS Benchmark Remediation (29 sections)"
echo "  Date: $(date)"
$DRY_RUN && echo "  MODE: DRY-RUN (aucun changement appliqué)"
echo "============================================================"
echo ""

run_section() {
    local num="$1"
    echo ""
    case "$num" in
        1)  section_1  ;;  2)  section_2  ;;  3)  section_3  ;;  4)  section_4  ;;
        5)  section_5  ;;  6)  section_6  ;;  7)  section_7  ;;  8)  section_8  ;;
        9)  section_9  ;;  10) section_10 ;;  11) section_11 ;;  12) section_12 ;;
        13) section_13 ;;  14) section_14 ;;  15) section_15 ;;  16) section_16 ;;
        17) section_17 ;;  18) section_18 ;;  19) section_19 ;;  20) section_20 ;;
        21) section_21 ;;  22) section_22 ;;  23) section_23 ;;  24) section_24 ;;
        25) section_25 ;;  26) section_26 ;;  27) section_27 ;;  28) section_28 ;;
        29) section_29 ;;
        *)  log_err "Section inconnue: $num"; exit 1 ;;
    esac
}

if [[ -n "$SECTION" ]]; then
    run_section "$SECTION"
else
    for i in $(seq 1 ${MAX_SECTION}); do
        run_section "$i"
    done
fi

# ============================================================
# RÉSUMÉ FINAL
# ============================================================
echo ""
echo "============================================================"
if $DRY_RUN; then
    echo "  [DRY-RUN] Simulation terminée — aucun changement appliqué"
else
    echo "  Remédiation terminée (${MAX_SECTION} sections)"
    echo ""
    echo "  ACTIONS REQUISES APRÈS EXÉCUTION :"
    echo "  1. Reboot              (kernel modules + sysctl + crypto-policies)"
    echo "  2. AIDE --init         Décommenter dans section 21 et relancer"
    echo "  3. sugroup             gpasswd -a <user> sugroup si besoin de su"
    echo "  4. FreeIPA             ipa pwpolicy-show / pwpolicy-mod"
    echo "  5. Scan OpenSCAP       Relancer pour confirmer la remédiation"
    echo "  6. gpgcheck            Maintenir gpgcheck=1 (compatible Satellite)"
fi
echo "============================================================"
