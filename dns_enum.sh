#!/usr/bin/env bash
# ================================================================
#  dns_enum.sh  —  DNS Enumeration Tool
#  Usage: sudo ./dns_enum.sh <IP>
#  by Debug
# ================================================================

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[0;33m'
BLU='\033[0;94m'; CYN='\033[0;36m'; WHT='\033[1;37m'
DIM='\033[2m';    RST='\033[0m';    BLD='\033[1m'

# ── تحقق ────────────────────────────────────────────────────────
[[ -z "$1" ]] && { echo -e "${RED}Usage: sudo $0 <IP>${RST}"; exit 1; }
TARGET="$1"

OUTDIR="dns_results"; mkdir -p "$OUTDIR"
TS=$(date +"%Y%m%d_%H%M%S")

# ── مساعدات الطباعة ─────────────────────────────────────────────
hdr() { echo -e "\n${BLU}${BLD}┌─────────────────────────────────────────────────────┐${RST}
${BLU}${BLD}│${RST}  ${YLW}${BLD}$1${RST}
${BLU}${BLD}└─────────────────────────────────────────────────────┘${RST}"; }

item()  { echo -e "  ${GRN}✔${RST}  ${WHT}$1${RST}  ${DIM}$2${RST}"; }
warn()  { echo -e "  ${YLW}⚠${RST}  $1"; }
found() { echo -e "  ${RED}${BLD}!!${RST} ${RED}$1${RST}"; }
miss()  { echo -e "  ${DIM}✗  $1${RST}"; }

# حفظ بدون ألوان
save() { echo -e "$1" | sed 's/\x1B\[[0-9;]*m//g' >> "$OUTFILE"; }

# dig نظيف — يسحب فقط سطور الإجابات الحقيقية
dig_clean() {
    # $1=type  $2=domain  $3=@server(optional)
    dig +noall +answer +nocookie "$2" "$1" ${3:+"$3"} 2>/dev/null \
        | grep -v '^\s*$'
}

# استخرج القيمة الأخيرة من سطر dig
last() { awk '{print $NF}'; }
# استخرج العمود الخامس فصاعداً
rest() { awk '{$1=$2=$3=$4=""; print $0}' | sed 's/^ *//'; }
# تصنيف الهوست بناءً على الاسم
_hint() {
    local n="${1,,}"
    local hints=()
    echo "$n" | grep -qE '^(mail|mx|smtp|pop|imap|webmail)'  && hints+=("📧 Mail Server")
    echo "$n" | grep -qE '^(ns|dns|nameserver)'              && hints+=("🔎 DNS Server")
    echo "$n" | grep -qE '^(dev|staging|test|uat|qa|lab)'   && hints+=("🧪 Dev/Test Env")
    echo "$n" | grep -qE '^(admin|panel|cp|cpanel|manage)'  && hints+=("⚙ Admin Panel")
    echo "$n" | grep -qE '^(vpn|remote|ras|ssl)'            && hints+=("🔒 VPN/Remote")
    echo "$n" | grep -qE '^(ftp|sftp|files|backup)'         && hints+=("📁 File Server")
    echo "$n" | grep -qE '^(api|ws|rest|graphql)'           && hints+=("🔌 API")
    echo "$n" | grep -qE '^(db|sql|mysql|mongo|redis|pg)'   && hints+=("🗄 Database")
    echo "$n" | grep -qE '^(git|svn|repo|ci|jenkins|build)' && hints+=("🏗 DevOps/CI")
    echo "$n" | grep -qE '^(dc|ad|ldap|kerberos|rdp|win)'   && hints+=("🏢 AD/Windows")
    echo "$n" | grep -qE '^(www|web|portal|app|shop)'       && hints+=("🌐 Web App")
    echo "$n" | grep -qE '^(internal|int|intranet|corp)'    && hints+=("🏠 Internal")
    echo "$n" | grep -qE '^(monitor|nagios|grafana|zabbix)' && hints+=("📊 Monitoring")
    if [[ ${#hints[@]} -gt 0 ]]; then
        echo " ← ${hints[*]}"
    fi
}

# ================================================================
#  FUNCTION: enum_subdomain — تعداد كامل على دومين فرعي
# ================================================================
enum_subdomain() {
    local SUB="$1"
    local DEPTH="${2:-1}"
    local PREFIX="  $(printf '  %.0s' $(seq 1 $DEPTH))"

    echo -e "\n${BLU}${BLD}  ┌── Enumerating: ${YLW}${SUB}${RST}"
    printf '\n  [ENUM: %s]\n' "$SUB" >> "$OUTFILE"

    local NS_SUB="@${TARGET}"

    # A record
    local A=$(dig +short A "$SUB" "$NS_SUB" 2>/dev/null | grep -E '^[0-9]')
    if [[ -n "$A" ]]; then
        echo -e "${PREFIX}${GRN}A${RST}     $(echo "$A" | tr '\n' '  ')"
        printf '    A: %s\n' "$A" >> "$OUTFILE"
    fi

    # CNAME
    local CN=$(dig +noall +answer CNAME "$SUB" "$NS_SUB" 2>/dev/null | awk '{print $NF}' | sed 's/\.$//')
    [[ -n "$CN" ]] && { echo -e "${PREFIX}${GRN}CNAME${RST} → $CN"; printf '    CNAME: %s\n' "$CN" >> "$OUTFILE"; }

    # MX
    local MX=$(dig +noall +answer MX "$SUB" "$NS_SUB" 2>/dev/null | awk '{print $5,$6}' | sed 's/\.$//g')
    [[ -n "$MX" ]] && { echo -e "${PREFIX}${GRN}MX${RST}    $MX"; printf '    MX: %s\n' "$MX" >> "$OUTFILE"; }

    # TXT
    local TXT=$(dig +noall +answer TXT "$SUB" "$NS_SUB" 2>/dev/null | awk '{$1=$2=$3=$4="";print}' | tr -d '"' | sed 's/^ *//')
    if [[ -n "$TXT" ]]; then
        while IFS= read -r t; do
            echo -e "${PREFIX}${GRN}TXT${RST}   ${t:0:80}"
            printf '    TXT: %s\n' "$t" >> "$OUTFILE"
        done <<< "$TXT"
    fi

    # NS
    local NSR=$(dig +noall +answer NS "$SUB" "$NS_SUB" 2>/dev/null | awk '{print $NF}' | sed 's/\.$//')
    [[ -n "$NSR" ]] && { echo -e "${PREFIX}${GRN}NS${RST}    $NSR"; printf '    NS: %s\n' "$NSR" >> "$OUTFILE"; }

    # SOA → admin email
    local SOA=$(dig +noall +answer SOA "$SUB" "$NS_SUB" 2>/dev/null)
    if [[ -n "$SOA" ]]; then
        local adm=$(echo "$SOA" | awk '{print $6}' | sed 's/\.\([^.]*\)$/@\1/' | sed 's/\.$//')
        [[ -n "$adm" ]] && { echo -e "${PREFIX}${GRN}SOA${RST}   admin: $adm"; printf '    SOA admin: %s\n' "$adm" >> "$OUTFILE"; }
    fi

    # AXFR
    local AXFR=$(dig axfr "$SUB" "$NS_SUB" 2>&1)
    if echo "$AXFR" | grep -q "XFR size:"; then
        echo -e "${PREFIX}${RED}${BLD}!! AXFR OPEN on ${SUB}${RST}"
        printf '    [VULN] AXFR open: %s\n' "$SUB" >> "$OUTFILE"
        echo "$AXFR" | grep -E '\sIN\s+A\s' | while IFS= read -r line; do
            local h=$(echo "$line" | awk '{print $1}' | sed 's/\.$//')
            local i=$(echo "$line" | awk '{print $NF}')
            echo -e "${PREFIX}  ${RED}✔${RST} $h  →  $i"
            printf '      %s -> %s\n' "$h" "$i" >> "$OUTFILE"
        done
    fi

    echo -e "${BLU}${BLD}  └──${RST}"
}

# ================================================================
#  FUNCTION: bruteforce_domain — brute-force على دومين معين
# ================================================================
# ================================================================
#  Mutation Attack — يجرب تباديل حول اسم مكتشف
#  مثال: ns.domain.htb  →  ns-word.domain.htb / word-ns.domain.htb
# ================================================================
permute_subdomain() {
    local LABEL="$1"       # e.g. "ns"
    local PARENT="$2"      # e.g. "domain.htb"
    local WORDLIST="$3"    # نفس الـ wordlist

    local MUT_FOUND=0
    local MUT_LIST=()

    echo -e "\n  ${YLW}↺${RST}  Mutation attack around ${BLD}${LABEL}${RST} in ${BLD}${PARENT}${RST}"
    printf '\n  [MUTATION: *%s*.%s]\n' "$LABEL" "$PARENT" >> "$OUTFILE"

    # ── أرقام سريعة أولاً (ns1,ns2,...,ns9,ns01...) ──────────────
    for n in $(seq 1 20) 01 02 03 04 05; do
        for cand in "${LABEL}${n}" "${LABEL}-${n}"; do
            local IP
            IP=$(dig +short A "${cand}.${PARENT}" "$NS" 2>/dev/null | grep -E '^[0-9]' | head -1)
            if [[ -n "$IP" ]]; then
                MUT_FOUND=$((MUT_FOUND+1))
                local HINT
                HINT=$(_hint "$cand")
                echo -e "  ${GRN}✔${RST}  ${WHT}${cand}.${PARENT}${RST}  ${DIM}${IP}${RST}${YLW}${HINT}${RST}"
                printf '  [MUT] %s.%s -> %s\n' "$cand" "$PARENT" "$IP" >> "$OUTFILE"
                MUT_LIST+=("${cand}.${PARENT}")
                echo "${cand}.${PARENT}    ${IP}" >> "$SUBFILE"
            fi
        done
    done

    # ── wordlist: جرب word-label و label-word ─────────────────────
    local COUNT=0 TOTAL
    TOTAL=$(wc -l < "$WORDLIST")
    local START_T=$SECONDS

    while IFS= read -r word; do
        [[ -z "$word" || "$word" == \#* ]] && continue
        COUNT=$((COUNT+1))

        for cand in "${LABEL}-${word}" "${word}-${LABEL}"; do
            local IP
            IP=$(dig +short A "${cand}.${PARENT}" "$NS" 2>/dev/null | grep -E '^[0-9]' | head -1)
            if [[ -n "$IP" ]]; then
                MUT_FOUND=$((MUT_FOUND+1))
                local HINT
                HINT=$(_hint "$cand")
                echo -e "  ${GRN}✔${RST}  ${WHT}${cand}.${PARENT}${RST}  ${DIM}${IP}${RST}${YLW}${HINT}${RST}"
                printf '  [MUT] %s.%s -> %s\n' "$cand" "$PARENT" "$IP" >> "$OUTFILE"
                MUT_LIST+=("${cand}.${PARENT}")
                echo "${cand}.${PARENT}    ${IP}" >> "$SUBFILE"
            fi
        done

        # progress كل 100
        if (( COUNT % 100 == 0 )); then
            local PCT=$(( COUNT * 100 / TOTAL ))
            local ELAPSED=$(( SECONDS - START_T ))
            local ETA=0
            (( ELAPSED > 0 && COUNT > 0 )) && ETA=$(( (TOTAL - COUNT) * ELAPSED / COUNT ))
            printf "\r  ${DIM}[MUT %d/%d] %d%%  |  found: %d  |  elapsed: %ds  |  eta: ~%ds${RST}   " \
                "$COUNT" "$TOTAL" "$PCT" "$MUT_FOUND" "$ELAPSED" "$ETA" >&2
        fi
    done < "$WORDLIST"

    echo -e "\n  ${GRN}✔${RST}  Mutation done — ${BLD}${MUT_FOUND}${RST} new hosts around '${LABEL}'"

    # إذا وُجدت نتائج، اعرض وخزّن
    if [[ ${#MUT_LIST[@]} -gt 0 ]]; then
        printf '  Found %d mutation results\n' "$MUT_FOUND" >> "$OUTFILE"
    fi
}

bruteforce_domain() {
    local TARGET_DOM="$1"
    local WORDLIST="$2"
    local DEPTH="${3:-1}"
    local INDENT="$(printf '  %.0s' $(seq 1 $DEPTH))"

    local FOUND_LIST=()
    local COUNT=0 FOUND=0
    local TOTAL=$(wc -l < "$WORDLIST")
    local START_T=$SECONDS

    echo -e "\n  ${GRN}[*]${RST} Brute-forcing ${BLD}*.${TARGET_DOM}${RST}  ($TOTAL entries)"
    printf '\n  [BRUTEFORCE: *.%s]\n' "$TARGET_DOM" >> "$OUTFILE"

    while IFS= read -r sub; do
        [[ -z "$sub" || "$sub" == \#* ]] && continue
        COUNT=$((COUNT+1))
        local FULL="${sub}.${TARGET_DOM}"
        local IP=$(dig +short A "$FULL" "$NS" 2>/dev/null | grep -E '^[0-9]' | head -1)
        if [[ -n "$IP" ]]; then
            FOUND=$((FOUND+1))
            local HINT=$(_hint "$sub")
            echo -e "  ${INDENT}${GRN}✔${RST}  ${WHT}${FULL}${RST}  ${DIM}${IP}${RST}${YLW}${HINT}${RST}"
            printf '  %s  ->  %s%s\n' "$FULL" "$IP" "$HINT" >> "$OUTFILE"
            FOUND_LIST+=("$FULL")
            echo "${FULL}    ${IP}" >> "$SUBFILE"
        fi
        # progress كل 100 مع نسبة ووقت
        if (( COUNT % 100 == 0 )); then
            local PCT=$(( COUNT * 100 / TOTAL ))
            local ELAPSED=$(( SECONDS - START_T ))
            local ETA=0
            (( ELAPSED > 0 && COUNT > 0 )) && ETA=$(( (TOTAL - COUNT) * ELAPSED / COUNT ))
            printf "\r  ${DIM}[%d/%d] %d%%  |  found: %d  |  elapsed: %ds  |  eta: ~%ds${RST}   " \
                "$COUNT" "$TOTAL" "$PCT" "$FOUND" "$ELAPSED" "$ETA" >&2
        fi
    done < "$WORDLIST"

    echo -e "\n  ${GRN}✔${RST}  ${BLD}${FOUND}${RST} found in *.${TARGET_DOM}"

    # إذا وُجدت نتائج، اسأل عن إعادة الـ enum
    if [[ ${#FOUND_LIST[@]} -gt 0 ]]; then
        echo ""
        echo -e "  ${CYN}[?]${RST} Found ${BLD}${#FOUND_LIST[@]}${RST} subdomains under ${BLD}${TARGET_DOM}${RST}."
        echo -e "      Re-enumerate each one? (DNS records + AXFR)"
        read -rp "$(echo -e "      ${YLW}[y/N]: ${RST}")" DO_ENUM
        if [[ "${DO_ENUM,,}" == "y" ]]; then
            for sub in "${FOUND_LIST[@]}"; do
                enum_subdomain "$sub" "$DEPTH"
            done
        fi

        # ── Mutation Attack ──────────────────────────────────────────
        echo ""
        echo -e "  ${CYN}[?]${RST} Run ${YLW}mutation attack${RST} on each found subdomain?"
        echo -e "      ${DIM}(tries: ns-word.domain, word-ns.domain, ns1..ns20 — same level)${RST}"
        read -rp "$(echo -e "      ${YLW}[y/N]: ${RST}")" DO_MUTATE
        if [[ "${DO_MUTATE,,}" == "y" ]]; then
            for full_sub in "${FOUND_LIST[@]}"; do
                local label
                label=$(echo "$full_sub" | cut -d'.' -f1)
                permute_subdomain "$label" "$TARGET_DOM" "$WORDLIST"
            done
        fi

        # ── Recursive Brute-Force ────────────────────────────────────
        if [[ $DEPTH -lt 3 ]]; then
            echo ""
            echo -e "  ${CYN}[?]${RST} Run deep brute-force on each found subdomain?"
            echo -e "      ${DIM}(e.g. find *.dev.domain.htb, *.mail.domain.htb ...)${RST}"
            read -rp "$(echo -e "      ${YLW}[y/N]: ${RST}")" DO_RECURSE
            if [[ "${DO_RECURSE,,}" == "y" ]]; then
                for sub in "${FOUND_LIST[@]}"; do
                    echo -e "\n  ${YLW}▶${RST}  Drilling into: ${BLD}${sub}${RST}"
                    bruteforce_domain "$sub" "$WORDLIST" $((DEPTH+1))
                done
            fi
        fi
    fi
}


# ================================================================
#  البداية — معرفة الدومين
# ================================================================
clear
echo -e "${BLU}${BLD}"
echo "  ██████╗ ███╗   ██╗███████╗    ███████╗███╗   ██╗██╗   ██╗███╗   ███╗"
echo "  ██╔══██╗████╗  ██║██╔════╝    ██╔════╝████╗  ██║██║   ██║████╗ ████║"
echo "  ██║  ██║██╔██╗ ██║███████╗    █████╗  ██╔██╗ ██║██║   ██║██╔████╔██║"
echo "  ██║  ██║██║╚██╗██║╚════██║    ██╔══╝  ██║╚██╗██║██║   ██║██║╚██╔╝██║"
echo "  ██████╔╝██║ ╚████║███████║    ███████╗██║ ╚████║╚██████╔╝██║ ╚═╝ ██║"
echo "  ╚═════╝ ╚═╝  ╚═══╝╚══════╝    ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝"
echo -e "${RST}"
echo -e "  ${DIM}Target: ${WHT}${TARGET}${RST}\n"

# ── اسأل عن الدومين ─────────────────────────────────────────────
echo -e "${CYN}[?]${RST} Do you already know the domain name for ${BLD}${TARGET}${RST}?"
echo -e "    ${DIM}(e.g. from nmap output or the lab description)${RST}"
read -rp "$(echo -e "    ${YLW}Enter domain [leave blank to auto-detect]: ${RST}")" USER_DOMAIN

if [[ -n "$USER_DOMAIN" ]]; then
    DOMAIN="$USER_DOMAIN"
    echo -e "  ${GRN}✔${RST}  Using: ${BLD}${DOMAIN}${RST}"
else
    echo -e "  ${CYN}[*]${RST}  Running PTR lookup..."
    PTR=$(dig -x "$TARGET" +short 2>/dev/null | head -1 | sed 's/\.$//')
    if [[ -z "$PTR" ]]; then
        echo -e "  ${YLW}⚠${RST}  No PTR record found."
        read -rp "$(echo -e "    ${YLW}Enter domain manually: ${RST}")" DOMAIN
        [[ -z "$DOMAIN" ]] && { echo -e "${RED}No domain. Exiting.${RST}"; exit 1; }
    else
        # استخرج الجذر من الـ FQDN
        DOMAIN=$(echo "$PTR" | awk -F'.' 'NF>=2{print $(NF-1)"."$NF}')
        echo -e "  ${GRN}✔${RST}  PTR → ${BLD}${PTR}${RST}  (domain: ${DOMAIN})"
    fi
fi

NS="@${TARGET}"
OUTFILE="${OUTDIR}/dns_${DOMAIN//./_}_${TS}.txt"

# هيدر التقرير
{
printf '%s\n' "================================================================"
printf '  DNS Enumeration Report\n'
printf '  Target  : %s\n' "$TARGET"
printf '  Domain  : %s\n' "$DOMAIN"
printf '  Date    : %s\n' "$(date)"
printf '%s\n\n' "================================================================"
} > "$OUTFILE"

# ================================================================
#  /etc/hosts
# ================================================================
hdr "Adding to /etc/hosts"

ENTRY="${TARGET}    ${DOMAIN}"
if grep -q "$TARGET" /etc/hosts 2>/dev/null; then
    existing=$(grep "$TARGET" /etc/hosts)
    warn "Already in /etc/hosts:"
    echo -e "    ${DIM}${existing}${RST}"
    save "[HOSTS] Already present: ${existing}"
else
    if [[ $EUID -ne 0 ]]; then
        echo "$ENTRY" | sudo tee -a /etc/hosts >/dev/null
    else
        echo "$ENTRY" >> /etc/hosts
    fi
    item "Added" "${ENTRY}"
    save "[HOSTS] Added: ${ENTRY}"
fi

# ================================================================
#  NS Records
# ================================================================
hdr "Nameservers (NS)"
save "--- NS Records ---"

NS_DATA=$(dig_clean NS "$DOMAIN" "$NS")
if [[ -n "$NS_DATA" ]]; then
    while IFS= read -r line; do
        ns_name=$(echo "$line" | last)
        ns_ip=$(dig_clean A "${ns_name%%.}" 2>/dev/null | last | head -1)
        item "$ns_name" "${ns_ip:-}"
        save "  NS: $ns_name  ($ns_ip)"
    done <<< "$NS_DATA"
else
    miss "No NS records"
fi

# ================================================================
#  MX Records
# ================================================================
hdr "Mail Servers (MX)"
save ""$'\n'"--- MX Records ---"

MX_DATA=$(dig_clean MX "$DOMAIN" "$NS")
if [[ -n "$MX_DATA" ]]; then
    while IFS= read -r line; do
        priority=$(echo "$line" | awk '{print $5}')
        mx_host=$(echo "$line"  | awk '{print $6}' | sed 's/\.$//')
        item "[${priority}] ${mx_host}"
        save "  MX: [$priority] $mx_host"
    done <<< "$MX_DATA"
else
    miss "No MX records"
fi

# ================================================================
#  TXT Records
# ================================================================
hdr "TXT Records  (SPF / DMARC / Verification)"
save ""$'\n'"--- TXT Records ---"

TXT_DATA=$(dig_clean TXT "$DOMAIN" "$NS")
if [[ -n "$TXT_DATA" ]]; then
    while IFS= read -r line; do
        val=$(echo "$line" | rest | tr -d '"')
        # تصنيف
        if   echo "$val" | grep -qi "v=spf";     then tag="SPF"
        elif echo "$val" | grep -qi "v=dmarc";   then tag="DMARC"
        elif echo "$val" | grep -qi "v=dkim";    then tag="DKIM"
        elif echo "$val" | grep -qi "google-site\|MS=\|facebook\|apple-domain"; then tag="VERIFY"
        else tag="TXT"
        fi
        item "[${tag}]" "${val:0:90}"
        save "  TXT [$tag]: $val"
    done <<< "$TXT_DATA"
else
    miss "No TXT records"
fi

# ================================================================
#  A / AAAA Records
# ================================================================
hdr "A / AAAA Records"
save ""$'\n'"--- A Records ---"

A_DATA=$(dig_clean A "$DOMAIN" "$NS")
if [[ -n "$A_DATA" ]]; then
    while IFS= read -r line; do
        ip=$(echo "$line" | last)
        ttl=$(echo "$line" | awk '{print $2}')
        item "$ip" "TTL=${ttl}"
        save "  A: $ip  (TTL=$ttl)"
    done <<< "$A_DATA"
else
    miss "No A records"
fi

save ""$'\n'"--- AAAA Records ---"
AAAA_DATA=$(dig_clean AAAA "$DOMAIN" "$NS")
if [[ -n "$AAAA_DATA" ]]; then
    while IFS= read -r line; do
        ip=$(echo "$line" | last)
        item "$ip"
        save "  AAAA: $ip"
    done <<< "$AAAA_DATA"
else
    miss "No AAAA records"
fi

# ================================================================
#  SOA Record
# ================================================================
hdr "SOA Record"
save ""$'\n'"--- SOA Record ---"

SOA_DATA=$(dig_clean SOA "$DOMAIN" "$NS")
if [[ -n "$SOA_DATA" ]]; then
    primary=$(echo "$SOA_DATA" | awk '{print $5}' | sed 's/\.$//')
    admin=$(echo "$SOA_DATA"   | awk '{print $6}' | sed 's/\.\([^.]*\)$/@\1/' | sed 's/\.$//')
    serial=$(echo "$SOA_DATA"  | awk '{print $7}')
    item "Primary NS"  "$primary"
    item "Admin Email" "$admin"
    item "Serial"      "$serial"
    save "  Primary NS  : $primary"
    save "  Admin Email : $admin"
    save "  Serial      : $serial"
else
    miss "No SOA record"
fi

# ================================================================
#  ANY Query — كل السجلات دفعة واحدة
# ================================================================
hdr "ANY Query (All Records)"
printf '\n--- ANY Query ---\n' >> "$OUTFILE"

ANY_DATA=$(dig +noall +answer +additional "$DOMAIN" ANY "$NS" 2>/dev/null | grep -v '^\s*$')
if [[ -n "$ANY_DATA" ]]; then
    while IFS= read -r line; do
        rtype=$(echo "$line" | awk '{print $4}')
        rval=$(echo  "$line" | awk '{$1=$2=$3=$4="";print}' | sed 's/^ *//' | tr -d '"')
        echo -e "  ${GRN}[${rtype}]${RST}  ${rval}"
        printf '  [%s]: %s\n' "$rtype" "$rval" >> "$OUTFILE"
    done <<< "$ANY_DATA"
else
    miss "Server refused ANY query (common on hardened DNS)"
    printf '  ANY query refused\n' >> "$OUTFILE"
fi

# ================================================================
#  CNAME Records
# ================================================================
hdr "CNAME Records"
printf '\n--- CNAME Records ---\n' >> "$OUTFILE"

CNAME_DATA=$(dig +noall +answer "$DOMAIN" CNAME "$NS" 2>/dev/null | grep -v '^\s*$')
if [[ -n "$CNAME_DATA" ]]; then
    while IFS= read -r line; do
        alias=$(echo "$line" | awk '{print $NF}' | sed 's/\.$//')
        item "$DOMAIN" "→ $alias"
        printf '  CNAME: %s -> %s\n' "$DOMAIN" "$alias" >> "$OUTFILE"
    done <<< "$CNAME_DATA"
else
    miss "No CNAME records"
fi

# ================================================================
#  SRV Records — اكتشاف الخدمات
# ================================================================
hdr "SRV Records  (Service Discovery)"
printf '\n--- SRV Records ---\n' >> "$OUTFILE"

SRV_SERVICES=(
    "_ldap._tcp"          "_ldap._tcp.dc._msdcs"
    "_kerberos._tcp"      "_kerberos._udp"
    "_gc._tcp"            "_kpasswd._tcp"
    "_http._tcp"          "_https._tcp"
    "_sip._tcp"           "_sip._udp"
    "_sipfederationtls._tcp"
    "_ftp._tcp"           "_ssh._tcp"
    "_smtp._tcp"          "_pop3._tcp"
    "_imap._tcp"          "_imaps._tcp"
    "_xmpp-client._tcp"   "_xmpp-server._tcp"
    "_caldav._tcp"        "_carddav._tcp"
    "_minecraft._tcp"     "_rdp._tcp"
    "_vnc._tcp"           "_nfs._tcp"
)

SRV_FOUND=0
for svc in "${SRV_SERVICES[@]}"; do
    SRV_DATA=$(dig +noall +answer "${svc}.${DOMAIN}" SRV "$NS" 2>/dev/null | grep -v '^\s*$')
    if [[ -n "$SRV_DATA" ]]; then
        SRV_FOUND=$((SRV_FOUND+1))
        while IFS= read -r line; do
            prio=$(echo "$line" | awk '{print $5}')
            wgt=$(echo  "$line" | awk '{print $6}')
            port=$(echo "$line" | awk '{print $7}')
            tgt=$(echo  "$line" | awk '{print $8}' | sed 's/\.$//')
            item "${svc}.${DOMAIN}" "→ ${tgt}:${port}  (prio=${prio} w=${wgt})"
            printf '  SRV %s -> %s:%s\n' "${svc}.${DOMAIN}" "$tgt" "$port" >> "$OUTFILE"
        done <<< "$SRV_DATA"
    fi
done
[[ $SRV_FOUND -eq 0 ]] && miss "No SRV records found"

# ================================================================
#  PTR — Reverse Lookup للـ IPs المكتشفة
# ================================================================
hdr "PTR Reverse Lookups  (Discovered IPs)"
printf '\n--- PTR Lookups ---\n' >> "$OUTFILE"

# اجمع كل IPs من A records
ALL_IPS=()
while IFS= read -r line; do
    ip=$(echo "$line" | last)
    [[ "$ip" =~ ^[0-9] ]] && ALL_IPS+=("$ip")
done <<< "$(dig +noall +answer "$DOMAIN" A "$NS" 2>/dev/null)"

if [[ ${#ALL_IPS[@]} -eq 0 ]]; then
    miss "No IPs to reverse lookup"
else
    for ip in "${ALL_IPS[@]}"; do
        PTR_VAL=$(dig -x "$ip" +short "$NS" 2>/dev/null | sed 's/\.$//')
        if [[ -n "$PTR_VAL" ]]; then
            item "$ip" "→ $PTR_VAL"
            printf '  PTR %s -> %s\n' "$ip" "$PTR_VAL" >> "$OUTFILE"
        else
            miss "${ip}  —  no PTR"
        fi
    done
fi

# ================================================================
#  Wildcard Detection
# ================================================================
hdr "Wildcard DNS Detection"
printf '\n--- Wildcard Detection ---\n' >> "$OUTFILE"

RAND_SUB="thisdoesnotexist$(date +%s)"
WC=$(dig +short "${RAND_SUB}.${DOMAIN}" A "$NS" 2>/dev/null | grep -E '^[0-9]' | head -1)
if [[ -n "$WC" ]]; then
    warn "WILDCARD DETECTED! *.${DOMAIN} → ${WC}"
    warn "Brute-force results may be unreliable!"
    printf '  [WILDCARD] *.%s -> %s\n' "$DOMAIN" "$WC" >> "$OUTFILE"
else
    item "No wildcard" "*.${DOMAIN} → NXDOMAIN"
    printf '  No wildcard detected\n' >> "$OUTFILE"
fi

# ================================================================
#  AXFR على كل NS Server مكتشف
# ================================================================
hdr "Zone Transfer on All NS Servers"
printf '\n--- AXFR on all NS servers ---\n' >> "$OUTFILE"

NS_LIST=$(dig +noall +answer "$DOMAIN" NS "$NS" 2>/dev/null | awk '{print $NF}' | sed 's/\.$//')
if [[ -z "$NS_LIST" ]]; then
    miss "No NS servers found to try"
else
    while IFS= read -r ns_name; do
        ns_ip=$(dig +short "$ns_name" A 2>/dev/null | grep -E '^[0-9]' | head -1)
        [[ -z "$ns_ip" ]] && continue
        echo -e "  ${DIM}Trying AXFR via ${ns_name} (${ns_ip}) ...${RST}"
        AXFR_NS=$(dig axfr "$DOMAIN" "@${ns_ip}" 2>&1)
        if echo "$AXFR_NS" | grep -q "XFR size:"; then
            found "AXFR OPEN via NS: ${ns_name} (${ns_ip})"
            printf '  [VULN] AXFR via %s (%s)\n' "$ns_name" "$ns_ip" >> "$OUTFILE"
            echo "$AXFR_NS" | grep -E '\sIN\s+A\s' | while IFS= read -r line; do
                h=$(echo "$line" | awk '{print $1}' | sed 's/\.$//')
                i=$(echo "$line" | awk '{print $NF}')
                item "  $h" "$i"
                printf '    %s -> %s\n' "$h" "$i" >> "$OUTFILE"
            done
        else
            miss "${ns_name}  —  AXFR refused"
        fi
    done <<< "$NS_LIST"
fi

# ================================================================
#  NSEC Walking — DNSSEC Zone Enumeration
# ================================================================
hdr "DNSSEC / NSEC Check"
printf '\n--- DNSSEC / NSEC ---\n' >> "$OUTFILE"

DNSKEY=$(dig +noall +answer "$DOMAIN" DNSKEY "$NS" 2>/dev/null)
NSEC=$(dig +noall +answer "$DOMAIN" NSEC "$NS" 2>/dev/null)
DS=$(dig +noall +answer "$DOMAIN" DS "$NS" 2>/dev/null)

if [[ -n "$DNSKEY" ]]; then
    item "DNSSEC Enabled" "DNSKEY found"
    printf '  DNSSEC: enabled\n' >> "$OUTFILE"
    # طباعة algorithm
    while IFS= read -r line; do
        algo=$(echo "$line" | awk '{print $7}')
        bits=$(echo "$line" | awk '{print $6}')
        flag=$(echo "$line" | awk '{print $5}')
        label="ZSK"; [[ "$flag" == "257" ]] && label="KSK"
        item "  [$label] Algo=${algo}" "Flags=${flag}"
        printf '  [%s] Algorithm=%s Flags=%s\n' "$label" "$algo" "$flag" >> "$OUTFILE"
    done <<< "$DNSKEY"
    # NSEC — يكشف الأسماء المجاورة في الـ zone
    if [[ -n "$NSEC" ]]; then
        warn "NSEC (not NSEC3) — Zone Walking possible!"
        printf '  [WARN] NSEC walking possible\n' >> "$OUTFILE"
        echo -e "  ${DIM}Try: ldns-walk @${TARGET} ${DOMAIN}${RST}"
    fi
else
    miss "DNSSEC not enabled"
    printf '  DNSSEC: not enabled\n' >> "$OUTFILE"
fi

# ================================================================
#  Common Subdomains — Quick Wins قبل الـ Brute-Force
# ================================================================
hdr "Common Subdomains  (Quick Wins)"
printf '\n--- Common Subdomains ---\n' >> "$OUTFILE"

COMMON_SUBS=(
    www mail smtp pop imap ftp ssh admin portal
    api dev staging test uat qa vpn remote rdp
    internal intranet corp git svn jenkins ci
    db mysql mongo redis ldap dc ad ns dns
    webmail calendar docs files backup media
    monitor nagios grafana kibana elastic
    shop store cdn static assets proxy
)

QW_FOUND=0
for sub in "${COMMON_SUBS[@]}"; do
    ip=$(dig +short "${sub}.${DOMAIN}" A "$NS" 2>/dev/null | grep -E '^[0-9]' | head -1)
    if [[ -n "$ip" ]]; then
        QW_FOUND=$((QW_FOUND+1))
        HINT=$(_hint "$sub")
        echo -e "  ${GRN}✔${RST}  ${WHT}${sub}.${DOMAIN}${RST}  ${DIM}${ip}${RST}${YLW}${HINT}${RST}"
        printf '  %s.%s  ->  %s\n' "$sub" "$DOMAIN" "$ip" >> "$OUTFILE"
        # أضفه للـ SUBFILE إن وُجد
        echo "${sub}.${DOMAIN}    ${ip}" >> "$SUBFILE" 2>/dev/null || true
    fi
done
[[ $QW_FOUND -eq 0 ]] && miss "No common subdomains found"
echo -e "  ${DIM}Found ${QW_FOUND} / ${#COMMON_SUBS[@]} common subdomains${RST}"

# ================================================================
#  CHAOS — Server Version
# ================================================================
hdr "DNS Server Fingerprint (CHAOS)"
save ""$'\n'"--- CHAOS Version ---"

CHAOS=$(dig +noall +answer CH TXT version.bind "$TARGET" 2>/dev/null | grep -i "version" | rest | tr -d '"')
CHAOS2=$(dig +noall +answer CH TXT version.server "$TARGET" 2>/dev/null | rest | tr -d '"')
HOSTNAME_BIND=$(dig +noall +answer CH TXT hostname.bind "$TARGET" 2>/dev/null | rest | tr -d '"')

if [[ -n "$CHAOS" ]]; then
    item "Version" "$CHAOS"
    save "  Version: $CHAOS"
else
    miss "version.bind  —  hidden"
fi
if [[ -n "$HOSTNAME_BIND" ]]; then
    item "Hostname" "$HOSTNAME_BIND"
    save "  Hostname: $HOSTNAME_BIND"
fi

# ================================================================
#  Zone Transfer (AXFR)
# ================================================================
hdr "Zone Transfer  (AXFR)"
printf '\n--- Zone Transfer ---\n' >> "$OUTFILE"

# مؤقت لتجميع الهوستات عبر subshell
AXFR_TMP=$(mktemp)

_axfr_try() {
    local dom="$1" label="${2:-}"
    local result
    result=$(dig axfr "$dom" "$NS" 2>&1)

    if ! echo "$result" | grep -q "XFR size:"; then
        miss "$dom  —  AXFR not allowed"
        printf '  AXFR not allowed: %s\n' "$dom" >> "$OUTFILE"
        return 1
    fi

    found "AXFR OPEN${label:+ ($label)} — Zone Transfer Vulnerability!"
    printf '  [VULN] AXFR open: %s\n' "$dom" >> "$OUTFILE"
    echo ""

    # ── A Records ────────────────────────────────────────────────
    local a_out
    a_out=$(echo "$result" | grep -E '\sIN\s+A\s' | grep -v 'AAAA')
    if [[ -n "$a_out" ]]; then
        echo -e "  ${WHT}[A Records]${RST}"
        printf '  [A Records]\n' >> "$OUTFILE"
        while IFS= read -r line; do
            local h i
            h=$(echo "$line" | awk '{print $1}' | sed 's/\.$//')
            i=$(echo "$line" | awk '{print $NF}')
            item "$h" "$i"
            printf '    %s  ->  %s\n' "$h" "$i" >> "$OUTFILE"
            [[ "$h" != "$dom" ]] && echo "$h" >> "$AXFR_TMP"
        done <<< "$a_out"
        echo ""
    fi

    # ── AAAA Records ─────────────────────────────────────────────
    local aaaa_out
    aaaa_out=$(echo "$result" | grep -E '\sIN\s+AAAA\s')
    if [[ -n "$aaaa_out" ]]; then
        echo -e "  ${WHT}[AAAA Records]${RST}"
        printf '  [AAAA Records]\n' >> "$OUTFILE"
        while IFS= read -r line; do
            local h i
            h=$(echo "$line" | awk '{print $1}' | sed 's/\.$//')
            i=$(echo "$line" | awk '{print $NF}')
            item "$h" "$i"
            printf '    %s  ->  %s\n' "$h" "$i" >> "$OUTFILE"
        done <<< "$aaaa_out"
        echo ""
    fi

    # ── CNAME Records ────────────────────────────────────────────
    local cname_out
    cname_out=$(echo "$result" | grep -E '\sIN\s+CNAME\s')
    if [[ -n "$cname_out" ]]; then
        echo -e "  ${WHT}[CNAME Records]${RST}"
        printf '  [CNAME Records]\n' >> "$OUTFILE"
        while IFS= read -r line; do
            local n a
            n=$(echo "$line" | awk '{print $1}' | sed 's/\.$//')
            a=$(echo "$line" | awk '{print $NF}' | sed 's/\.$//')
            item "[CNAME] $n" "→ $a"
            printf '    CNAME: %s -> %s\n' "$n" "$a" >> "$OUTFILE"
        done <<< "$cname_out"
        echo ""
    fi

    # ── MX Records ───────────────────────────────────────────────
    local mx_out
    mx_out=$(echo "$result" | grep -E '\sIN\s+MX\s')
    if [[ -n "$mx_out" ]]; then
        echo -e "  ${WHT}[MX Records]${RST}"
        printf '  [MX Records]\n' >> "$OUTFILE"
        while IFS= read -r line; do
            local prio mx
            prio=$(echo "$line" | awk '{print $5}')
            mx=$(echo "$line"   | awk '{print $6}' | sed 's/\.$//')
            item "[${prio}] $mx"
            printf '    MX [%s]: %s\n' "$prio" "$mx" >> "$OUTFILE"
        done <<< "$mx_out"
        echo ""
    fi

    # ── NS Records ───────────────────────────────────────────────
    local ns_out
    ns_out=$(echo "$result" | grep -E '\sIN\s+NS\s')
    if [[ -n "$ns_out" ]]; then
        echo -e "  ${WHT}[NS Records]${RST}"
        printf '  [NS Records]\n' >> "$OUTFILE"
        while IFS= read -r line; do
            local ns
            ns=$(echo "$line" | awk '{print $NF}' | sed 's/\.$//')
            item "$ns"
            printf '    NS: %s\n' "$ns" >> "$OUTFILE"
        done <<< "$ns_out"
        echo ""
    fi

    # ── SOA Record ───────────────────────────────────────────────
    local soa_out
    soa_out=$(echo "$result" | grep -E '\sIN\s+SOA\s' | head -1)
    if [[ -n "$soa_out" ]]; then
        echo -e "  ${WHT}[SOA Record]${RST}"
        local pns adm serial
        pns=$(echo "$soa_out"    | awk '{print $5}' | sed 's/\.$//')
        adm=$(echo "$soa_out"    | awk '{print $6}' | sed 's/\.\([^.]*\)$/@\1/' | sed 's/\.$//')
        serial=$(echo "$soa_out" | awk '{print $7}')
        item "Primary NS"  "$pns"
        item "Admin Email" "$adm"
        item "Serial"      "$serial"
        printf '  [SOA]\n    Primary NS  : %s\n    Admin Email : %s\n    Serial      : %s\n' \
            "$pns" "$adm" "$serial" >> "$OUTFILE"
        echo ""
    fi

    # ── TXT Records ── الأهم: flags / secrets / verify tokens ────
    local txt_out
    txt_out=$(echo "$result" | grep -E '\sIN\s+TXT\s')
    if [[ -n "$txt_out" ]]; then
        echo -e "  ${WHT}[TXT Records]${RST}"
        printf '  [TXT Records]\n' >> "$OUTFILE"
        while IFS= read -r line; do
            local val
            val=$(echo "$line" | awk '{$1=$2=$3=$4="";print}' | tr -d '"' | sed 's/^ *//')
            # تصنيف DNS حقيقي
            local tag color
            if   echo "$val" | grep -qi 'v=spf';                                             then tag="SPF";    color="$GRN"
            elif echo "$val" | grep -qi 'v=dmarc';                                            then tag="DMARC";  color="$GRN"
            elif echo "$val" | grep -qi 'v=dkim';                                             then tag="DKIM";   color="$GRN"
            elif echo "$val" | grep -qE 'MS=ms|google-site|atlassian|docusign|facebook|apple'; then tag="VERIFY"; color="$CYN"
            else tag="TXT"; color="$WHT"
            fi
            echo -e "  ${color}[${tag}]${RST}  ${val}"
            printf '    [%s]: %s\n' "$tag" "$val" >> "$OUTFILE"
        done <<< "$txt_out"
        echo ""
    fi

    # ── PTR Records ──────────────────────────────────────────────
    local ptr_out
    ptr_out=$(echo "$result" | grep -E '\sIN\s+PTR\s')
    if [[ -n "$ptr_out" ]]; then
        echo -e "  ${WHT}[PTR Records]${RST}"
        printf '  [PTR Records]\n' >> "$OUTFILE"
        while IFS= read -r line; do
            local p t
            p=$(echo "$line" | awk '{print $1}')
            t=$(echo "$line" | awk '{print $NF}' | sed 's/\.$//')
            item "$p" "→ $t"
            printf '    %s -> %s\n' "$p" "$t" >> "$OUTFILE"
        done <<< "$ptr_out"
        echo ""
    fi

    return 0
}

echo -e "  ${DIM}Trying ${DOMAIN} ...${RST}"
_axfr_try "$DOMAIN"

echo -e "\n  ${DIM}Trying internal.${DOMAIN} ...${RST}"
_axfr_try "internal.${DOMAIN}" "internal"

# ── سؤال: brute-force على كل هوست طلع من AXFR؟ ────────────────
AXFR_HOSTS=()
if [[ -s "$AXFR_TMP" ]]; then
    while IFS= read -r h; do
        [[ -n "$h" ]] && AXFR_HOSTS+=("$h")
    done < "$AXFR_TMP"
fi
rm -f "$AXFR_TMP"

if [[ ${#AXFR_HOSTS[@]} -gt 0 ]]; then
    echo ""
    echo -e "  ${CYN}[?]${RST} AXFR revealed ${BLD}${#AXFR_HOSTS[@]}${RST} hosts:"
    for h in "${AXFR_HOSTS[@]}"; do
        echo -e "      ${DIM}• $h${RST}"
    done
    echo ""
    echo -e "  ${CYN}[?]${RST} Run brute-force on each of these subdomains?"
    echo -e "      ${DIM}(finds deeper hosts like win2k.dev.domain.htb)${RST}"
    read -rp "$(echo -e "      ${YLW}[y/N]: ${RST}")" BF_AXFR_HOSTS

    if [[ "${BF_AXFR_HOSTS,,}" == "y" ]]; then
        # نحتاج wordlist — نسأل عنه هنا أو نستخدم الافتراضي
        _DEF_WL="/opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt"
        [[ ! -f "$_DEF_WL" ]] && _DEF_WL="/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt"
        [[ ! -f "$_DEF_WL" ]] && _DEF_WL="/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt"

        if [[ ! -f "$_DEF_WL" ]]; then
            read -rp "$(echo -e "      ${YLW}Wordlist path: ${RST}")" _DEF_WL
        else
            read -rp "$(echo -e "      ${YLW}Wordlist [Enter=default]: ${RST}")" _WL_INPUT
            [[ -n "$_WL_INPUT" ]] && _DEF_WL="$_WL_INPUT"
        fi

        if [[ -f "$_DEF_WL" ]]; then
            SUBFILE="${OUTDIR}/subdomains_${DOMAIN//./_}_${TS}.txt"
            for axfr_host in "${AXFR_HOSTS[@]}"; do
                echo -e "\n  ${YLW}▶${RST}  Brute-forcing: ${BLD}${axfr_host}${RST}"
                bruteforce_domain "$axfr_host" "$_DEF_WL" 1
            done
        else
            warn "Wordlist not found — skipping"
        fi
    fi
fi


# ================================================================
#  Subdomain Brute-Force (Main)
# ================================================================
hdr "Subdomain Brute-Force"

DEFAULT_WL="/opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt"
[[ ! -f "$DEFAULT_WL" ]] && DEFAULT_WL="/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt"
[[ ! -f "$DEFAULT_WL" ]] && DEFAULT_WL="/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt"

echo -e "  ${CYN}[?]${RST} Run subdomain brute-force on ${BLD}${DOMAIN}${RST}?"
[[ -f "$DEFAULT_WL" ]] && echo -e "      Wordlist: ${DIM}${DEFAULT_WL}${RST}  ($(wc -l < "$DEFAULT_WL") entries)"
echo ""
read -rp "$(echo -e "      ${YLW}Run? [y/N]: ${RST}")" RUN_BF

SUBFILE="${OUTDIR}/subdomains_${DOMAIN//./_}_${TS}.txt"

if [[ "${RUN_BF,,}" == "y" ]]; then
    if [[ ! -f "$DEFAULT_WL" ]]; then
        read -rp "$(echo -e "      ${YLW}Wordlist path: ${RST}")" WORDLIST
    else
        read -rp "$(echo -e "      ${YLW}Wordlist [Enter=default]: ${RST}")" WORDLIST
        [[ -z "$WORDLIST" ]] && WORDLIST="$DEFAULT_WL"
    fi

    if [[ ! -f "$WORDLIST" ]]; then
        warn "Wordlist not found: $WORDLIST"
    else
        bruteforce_domain "$DOMAIN" "$WORDLIST" 1
    fi
else
    miss "Skipped"
fi

# ================================================================
#  Done
# ================================================================
hdr "Done"
echo ""
echo -e "  ${GRN}${BLD}Report :${RST}  ${OUTFILE}"
[[ -f "$SUBFILE" ]] && echo -e "  ${GRN}${BLD}Subs   :${RST}  ${SUBFILE}"
echo ""
