# AgentSec Server Security

Use this reference for Linux host hardening and authorized external server exposure reviews.

## Contents

- External surface
- Patch management
- SSH
- Firewall and service binding
- Web servers and document roots
- Databases and caches
- Permissions and privileged execution
- Containers
- Scheduled tasks and services
- Logging and verification

## External surface

Treat every listening service as an inventory item, not automatically a vulnerability.

For each listener determine:

- Is the service required?
- Does it need to be reachable from the public Internet?
- Is it bound to the intended interface?
- Is authentication enabled and strong?
- Is transport encryption required and correctly configured?
- Is the service/version supported and patched?
- Is a reverse proxy/VPN/private network expected to be the real boundary?

Common high-risk accidental exposures include Docker APIs, databases, Redis, Elasticsearch/OpenSearch, Memcached, dashboards, control panels, metrics endpoints, message brokers and internal development servers.

## Patch management

Review OS and application patch status, kernel/security updates, end-of-life distributions, stale container images and unsupported runtime versions.

Do not blindly upgrade a production system during an audit. Identify the required patch, compatibility/reboot impact and maintenance procedure first.

## SSH

Review effective `sshd` configuration, not only commented defaults.

Important controls include:

- Disable direct root login unless there is a documented exceptional requirement.
- Prefer public-key or stronger identity-based authentication over exposed password authentication.
- Disable empty passwords.
- Restrict users/groups where operationally appropriate.
- Limit authentication attempts and unnecessary forwarding features.
- Remove obsolete algorithms rather than copying arbitrary cipher lists from old hardening guides.
- Keep emergency/automation access paths documented so hardening does not lock operators out.

Validate configuration syntax before reload/restart.

## Firewall and service binding

Use defense in depth:

- Bind internal services to loopback/private interfaces when possible.
- Enforce host firewall rules for required source networks and ports.
- Also review cloud security groups/network ACLs/load-balancer listeners if the server is hosted in a cloud environment.
- Avoid using application-level authentication as the only protection for a management port that should not be Internet reachable.

Document expected ports so future drift is detectable.

## Web servers and document roots

Review Nginx/Apache/Caddy/reverse-proxy configuration for:

- directory listing/autoindex
- dotfile and source-control metadata exposure
- backups, logs, databases, keys and `.env` files under document roots
- default virtual hosts that expose unintended content
- server status/info endpoints
- unsafe aliases/symlinks
- upload directories that can execute scripts
- inconsistent authorization across nested locations/routes
- missing TLS redirects or unexpected plaintext management listeners
- verbose version/error disclosure
- unsafe proxy trust/header configuration

A Gobuster discovery is best fixed by proper access control and deployment layout, not by renaming the path.

## Databases and caches

Review MySQL/MariaDB, PostgreSQL, Redis, MongoDB, Elasticsearch/OpenSearch and other data services for:

- public binds/listeners
- weak/no authentication
- transport encryption where required
- excessive database/application privileges
- default/test users and databases
- remote administrative access
- backup file exposure
- stale versions

Prefer private network placement and least-privilege application accounts.

## Permissions and privileged execution

Investigate:

- unexpected SUID/SGID binaries
- writable systemd service/unit files or executable paths
- writable cron scripts/directories
- world-writable files in sensitive application/system paths
- secrets readable by unrelated users
- application processes running as root without need
- overly broad sudo rules

Do not remove standard distribution SUID binaries merely because they appear in a scan. Compare against package ownership/baseline and actual need.

## Containers

Review:

- `--privileged`
- Docker socket mounts
- host network/PID namespaces
- broad Linux capabilities
- root users
- writable root filesystems
- hostPath/bind mounts into sensitive host paths
- secrets in environment variables, image layers or build arguments
- stale/untrusted base images
- published ports bypassing intended reverse proxies/firewalls

Docker group/socket access is typically equivalent to root-level host control. Treat membership accordingly.

## Scheduled tasks and services

Review systemd units, timers, cron jobs and startup scripts for writable executables/configuration, unexpected network downloads, broad privileges, secrets in command lines/environment files and abandoned services.

Disable only after confirming the service is not operationally required.

## Logging and verification

Ensure security-relevant events are observable without logging secrets:

- authentication success/failure and privileged actions
- service/firewall changes
- application security events
- system update failures

After hardening:

1. Validate configuration syntax.
2. Keep an existing administrative session open when changing remote access controls.
3. Reload rather than restart when the service supports safe reloads.
4. Verify service health locally.
5. Verify intended external access and confirm unintended ports/routes are closed.
6. Record rollback steps for production changes.
