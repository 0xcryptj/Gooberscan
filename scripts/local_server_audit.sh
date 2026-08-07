#!/usr/bin/env bash
set -u

# AgentSec local Linux server audit.
# Read-only by design. It does not sudo, install software, edit configuration,
# restart services, or change firewall rules.

section() {
  printf '\n===== %s =====\n' "$1"
}

have() {
  command -v "$1" >/dev/null 2>&1
}

run_if() {
  local cmd="$1"
  shift
  if have "$cmd"; then
    "$cmd" "$@" 2>&1 || true
  else
    echo "[AgentSec] $cmd not installed"
  fi
}

section "SYSTEM"
uname -a 2>&1 || true
[ -r /etc/os-release ] && cat /etc/os-release
printf 'User: %s\n' "$(id 2>/dev/null || true)"
printf 'Hostname: %s\n' "$(hostname -f 2>/dev/null || hostname 2>/dev/null || true)"
printf 'Uptime: %s\n' "$(uptime 2>/dev/null || true)"

section "PATCH STATUS"
if have apt; then
  apt list --upgradable 2>/dev/null | head -n 250 || true
elif have dnf; then
  dnf check-update --security 2>&1 | head -n 250 || true
elif have yum; then
  yum check-update --security 2>&1 | head -n 250 || true
elif have pacman; then
  pacman -Qu 2>&1 | head -n 250 || true
else
  echo "[AgentSec] package-manager update check not available"
fi

section "LISTENING NETWORK SERVICES"
if have ss; then
  ss -tulpn 2>&1 || ss -tuln 2>&1 || true
elif have netstat; then
  netstat -tulpn 2>&1 || true
else
  echo "[AgentSec] neither ss nor netstat is installed"
fi

section "DATABASE AND MANAGEMENT PORT EXPOSURE"
if have ss; then
  ss -tuln 2>/dev/null | grep -E ':(22|2375|2376|3306|5432|6379|9200|9300|11211|27017|27018|5601|8080|8443)([[:space:]]|$)' || true
fi

echo "Review whether each listener is required and whether it binds only to the intended interface/network."

section "FIREWALL"
if have ufw; then
  ufw status verbose 2>&1 || true
elif have firewall-cmd; then
  firewall-cmd --state 2>&1 || true
  firewall-cmd --list-all 2>&1 || true
elif have nft; then
  nft list ruleset 2>&1 | head -n 500 || true
elif have iptables; then
  iptables -S 2>&1 | head -n 500 || true
else
  echo "[AgentSec] no supported firewall CLI detected"
fi

section "SSH HARDENING"
if have sshd; then
  sshd -T 2>&1 | grep -Ei '^(permitrootlogin|passwordauthentication|pubkeyauthentication|kbdinteractiveauthentication|challengeresponseauthentication|permitemptypasswords|maxauthtries|maxsessions|allowusers|allowgroups|x11forwarding|allowtcpforwarding|gatewayports|loglevel|clientaliveinterval|clientalivecountmax|ciphers|macs|kexalgorithms) ' || true
else
  echo "[AgentSec] sshd is not installed or not in PATH"
fi
if [ -r /etc/ssh/sshd_config ]; then
  echo "-- explicit sshd_config directives --"
  grep -Ev '^[[:space:]]*(#|$)' /etc/ssh/sshd_config 2>/dev/null | head -n 300 || true
fi

section "FAILED AND ENABLED SERVICES"
if have systemctl; then
  systemctl --failed --no-pager 2>&1 || true
  echo "-- enabled services --"
  systemctl list-unit-files --type=service --state=enabled --no-pager 2>&1 | head -n 300 || true
fi

section "SUID/SGID EXECUTABLES"
for base in /usr/bin /usr/sbin /bin /sbin /usr/local/bin /usr/local/sbin; do
  [ -d "$base" ] || continue
  find "$base" -xdev -type f \( -perm -4000 -o -perm -2000 \) -printf '%m %u:%g %p\n' 2>/dev/null || true
done

section "WORLD-WRITABLE SENSITIVE FILES"
for base in /etc /var/www /srv /opt; do
  [ -d "$base" ] || continue
  find "$base" -xdev -type f -perm -0002 -printf '%m %u:%g %p\n' 2>/dev/null | head -n 300 || true
done

section "WEB ROOT SENSITIVE ARTIFACTS"
for base in /var/www /srv/www /usr/share/nginx/html; do
  [ -d "$base" ] || continue
  echo "-- $base --"
  find "$base" -xdev -type f \( \
    -name '.env' -o -name '.git' -o -name '*.sql' -o -name '*.sqlite' -o \
    -name '*.db' -o -name '*.bak' -o -name '*.backup' -o -name '*.old' -o \
    -name '*.zip' -o -name '*.tar' -o -name '*.tar.gz' -o -name '*.pem' -o \
    -name '*.key' -o -name '*.log' -o -name 'phpinfo.php' \
  \) -printf '%m %u:%g %p\n' 2>/dev/null | head -n 500 || true
done

section "NGINX"
if have nginx; then
  nginx -T 2>&1 | grep -Ei '(^|[[:space:]])(server_tokens|autoindex|root|alias|listen|ssl_protocols|add_header|location|deny|allow)[[:space:]]' | head -n 500 || true
else
  echo "[AgentSec] nginx not detected"
fi

section "APACHE"
if have apache2ctl; then
  apache2ctl -S 2>&1 || true
  apache2ctl -t -D DUMP_RUN_CFG 2>&1 | head -n 300 || true
  grep -RniE 'Options[[:space:]].*Indexes|AllowOverride[[:space:]]+None|ServerTokens|ServerSignature' /etc/apache2 2>/dev/null | head -n 300 || true
elif have httpd; then
  httpd -S 2>&1 || true
else
  echo "[AgentSec] Apache not detected"
fi

section "DOCKER / CONTAINER EXPOSURE"
if [ -S /var/run/docker.sock ]; then
  ls -l /var/run/docker.sock 2>&1 || true
  echo "Docker socket exists. Membership in its owning group is effectively root-equivalent on typical Docker hosts."
fi
if have docker; then
  docker version 2>&1 | head -n 80 || true
  echo "-- running containers --"
  docker ps --no-trunc 2>&1 || true
  echo "-- privileged / host-network / sensitive mounts --"
  ids=$(docker ps -q 2>/dev/null || true)
  for id in $ids; do
    docker inspect "$id" --format '{{.Name}} privileged={{.HostConfig.Privileged}} network={{.HostConfig.NetworkMode}} pid={{.HostConfig.PidMode}} user={{.Config.User}} readonly={{.HostConfig.ReadonlyRootfs}} mounts={{range .Mounts}}{{.Source}}:{{.Destination}};{{end}}' 2>/dev/null || true
  done
fi

section "CRON AND SCHEDULED TASK PERMISSIONS"
for path in /etc/crontab /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
  [ -e "$path" ] && ls -ld "$path" 2>&1 || true
done

section "LYNIS"
if have lynis; then
  lynis audit system --quick --no-colors 2>&1 || true
else
  echo "[AgentSec] Lynis not installed; install it for deeper host-hardening checks."
fi

section "AGENTSEC INTERPRETATION NOTES"
cat <<'EOF'
- A listening port is not automatically vulnerable. Validate whether the service is required and properly network-restricted.
- A SUID/SGID binary is not automatically vulnerable. Compare unexpected entries with the OS/package baseline.
- Do not expose databases, Docker APIs, Redis, Elasticsearch, or admin panels directly to the public Internet unless there is a deliberate, hardened requirement.
- For web roots, remove secrets/backups from the served directory and disable directory indexing rather than relying on obscurity.
- Apply server changes only after understanding availability impact, then verify service health and configuration syntax.
EOF
