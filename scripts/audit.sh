#!/usr/bin/env bash
set -uo pipefail
export LC_ALL=C
PASS=0; FAIL=0
check() {
    local desc="$1" expected="$2" actual="$3"
    if [[ "$actual" == "$expected" ]]; then
        echo "  [OK]   $desc"; ((PASS+=1))
    else
        echo "  [FAIL] $desc (expected: '$expected', actual: '$actual')"; ((FAIL+=1))
    fi
}
echo "Configuration audit: $(hostname -f), $(date '+%Y-%m-%d %H:%M')"
sshd_config=$(sudo /usr/sbin/sshd -T 2>/dev/null) || sshd_config=''
ufw_status=$(sudo ufw status verbose 2>/dev/null) || ufw_status=''
echo '[1] SSH service'
check 'Root login disabled' no "$(awk '$1=="permitrootlogin" {print $2}' <<< "$sshd_config")"
check 'Password authentication disabled' no "$(awk '$1=="passwordauthentication" {print $2}' <<< "$sshd_config")"
# TODO 1: require at least one listening port and reject port 22.
nonstandard=$(awk '$1=="port" {n++; if ($2==22) bad=1} END {print (n>0 && !bad) ? "yes" : "no"}' <<< "$sshd_config")
check 'All SSH ports differ from 22' yes "$nonstandard"
# TODO 2: check the effective value rather than a configuration file.
check 'MaxAuthTries equals 3' 3 "$(awk '$1=="maxauthtries" {print $2}' <<< "$sshd_config")"
echo '[2] Firewall'
check 'Firewall active' active "$(awk '/^Status:/ {print $2}' <<< "$ufw_status")"
# TODO 3: extract the incoming policy from the verbose status.
check 'Default incoming policy is deny' deny "$(sed -n 's/^Default: \([^ ]*\) (incoming).*/\1/p' <<< "$ufw_status")"
echo '[3] Accounts'
awk -F: '$3>=1000 && $3<65534 {printf "    %s (uid=%s)\n",$1,$3}' /etc/passwd

echo '[4] Web server'
check 'Nginx service active' active "$(systemctl is-active nginx 2>/dev/null)"
nginx_syntax=invalid
if sudo /usr/sbin/nginx -t >/dev/null 2>&1; then nginx_syntax=valid; fi
check 'Nginx configuration syntax valid' valid "$nginx_syntax"

cert_min_days="${AUDIT_CERT_MIN_DAYS:-30}"
cert_lifetime=insufficient
if [[ "$cert_min_days" =~ ^[0-9]{1,5}$ ]] && (( 10#$cert_min_days <= 36500 )); then
    if openssl x509 -in /etc/ssl/certs/devops.crt -noout -checkend "$((10#$cert_min_days * 86400))" >/dev/null 2>&1; then
        cert_lifetime=sufficient
    fi
fi
check "Certificate valid for at least $cert_min_days days" sufficient "$cert_lifetime"

web_permissions=unsafe
if writable_paths=$(find /var/www/devops-site -perm -o+w -print 2>/dev/null) && \
   key_permissions=$(sudo stat -c '%a:%u' /etc/ssl/private/devops.key 2>/dev/null) && \
   [[ -z "$writable_paths" && "$key_permissions" == 600:0 ]]; then
    web_permissions=secure
fi
check 'No world-writable web paths; TLS key root-owned and mode 600' secure "$web_permissions"

echo '[5] Containerization'
check 'Docker service active' active "$(systemctl is-active docker 2>/dev/null)"
db_health=$(docker inspect -f '{{.State.Health.Status}}' app-db-1 2>/dev/null) || db_health=unavailable
check 'PostgreSQL container healthy' healthy "$db_health"

published_ports=unsafe
if listeners=$(ss -H -ltn 2>/dev/null); then
    published_ports=$(awk '
        $4 ~ /:(5000|5432)$/ {
            if ($4 != "127.0.0.1:5000" && $4 != "127.0.0.1:5432") bad=1
            if ($4 == "127.0.0.1:5000") app=1
        }
        END {print (app && !bad) ? "secure" : "unsafe"}
    ' <<< "$listeners")
fi
check 'App listens on 127.0.0.1:5000; no external ports 5000 or 5432' secure "$published_ports"
app_home=$(getent passwd devops | cut -d: -f6)
env_mode=$(stat -c '%a' "${app_home}/app/.env" 2>/dev/null) || env_mode=unavailable
check 'Server app/.env mode equals 600' 600 "$env_mode"

echo '[6] KR2'
kr2_dir="${KR2_DIR:-/home/devops/kr2}"
redis_id=$(docker compose --project-directory "$kr2_dir" ps -q redis 2>/dev/null) || redis_id=''
redis_health=unavailable
if [[ -n "$redis_id" ]]; then
    redis_health=$(docker inspect -f '{{.State.Health.Status}}' "$redis_id" 2>/dev/null) || redis_health=unavailable
fi
check 'KR2 Redis service healthy' healthy "$redis_health"
kr2_port=$(docker compose --project-directory "$kr2_dir" port app 8002 2>/dev/null) || kr2_port=unavailable
check 'KR2 app port published only on loopback' '127.0.0.1:8002' "$kr2_port"
kr2_env_mode=$(stat -c '%a' "$kr2_dir/.env" 2>/dev/null) || kr2_env_mode=unavailable
check 'KR2 .env mode equals 600' 600 "$kr2_env_mode"
kr2_certificate=insufficient
if openssl x509 -in /etc/ssl/certs/kr2.crt -noout -checkend 2592000 >/dev/null 2>&1; then
    kr2_certificate=sufficient
fi
check 'KR2 certificate valid for at least 30 days' sufficient "$kr2_certificate"
kr2_enabled=inactive
if [[ -L /etc/nginx/sites-enabled/kr2 && -e /etc/nginx/sites-enabled/kr2 ]]; then kr2_enabled=active; fi
check 'KR2 Nginx site enabled by symbolic link' active "$kr2_enabled"

echo "Passed: $PASS, failed: $FAIL"
[[ $FAIL -eq 0 ]] && exit 0 || exit 1
