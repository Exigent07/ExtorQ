#!/bin/sh
# /usr/local/sbin/extorq-provision: one-shot provisioning of the ExtorQ lab VM.
# Deployed by cloud-init (source: infra/vm/files/provision/extorq-provision.sh)
# and executed once by runcmd as root after packages and deferred files exist.
# Idempotent. Never prints secrets (no `set -x`).
set -eu
umask 077

log() { printf 'extorq-provision: %s\n' "$*"; }

# ── auditd: logs readable by group adm (the collector), ExtorQ rules loaded ──
AUDITD_CONF=/etc/audit/auditd.conf
if grep -q '^log_group' "$AUDITD_CONF"; then
  sed -i 's/^log_group[[:space:]]*=.*/log_group = adm/' "$AUDITD_CONF"
else
  printf 'log_group = adm\n' >>"$AUDITD_CONF"
fi
if grep -q '^log_format' "$AUDITD_CONF"; then
  sed -i 's/^log_format[[:space:]]*=.*/log_format = ENRICHED/' "$AUDITD_CONF"
else
  printf 'log_format = ENRICHED\n' >>"$AUDITD_CONF"
fi
chown root:adm /var/log/audit
chmod 0750 /var/log/audit
for f in /var/log/audit/audit.log*; do
  [ -e "$f" ] || continue
  chown root:adm "$f"
  chmod 0640 "$f"
done
systemctl kill --signal=SIGHUP auditd.service || true  # re-read auditd.conf
augenrules --load
log "audit rules loaded: $(auditctl -l | grep -c 'extorq_') extorq rules"

# ── nginx: only the ExtorQ lab site ──
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl enable nginx.service
systemctl restart nginx.service

# ── lab-portal demo credential: generated here, stored only inside the VM ──
CRED_DIR=/etc/extorq/lab-portal
install -d -m 0700 -o root -g root /etc/extorq "$CRED_DIR"
if [ ! -s "$CRED_DIR/demo_password_hash" ]; then
  pw="$(python3 -I -c 'import secrets; print(secrets.token_urlsafe(18))')"
  printf '%s\n' "$pw" | python3 -I /opt/extorq/lab-portal/app.py --hash-password \
    >"$CRED_DIR/demo_password_hash.tmp"
  printf 'username=lab-admin\npassword=%s\n' "$pw" >"$CRED_DIR/demo-credentials.tmp"
  pw=""
  chmod 0600 "$CRED_DIR/demo_password_hash.tmp" "$CRED_DIR/demo-credentials.tmp"
  mv "$CRED_DIR/demo_password_hash.tmp" "$CRED_DIR/demo_password_hash"
  mv "$CRED_DIR/demo-credentials.tmp" "$CRED_DIR/demo-credentials"
  log "lab-portal demo credential generated (root-only: $CRED_DIR/demo-credentials)"
fi
systemctl daemon-reload
systemctl enable lab-portal.service
systemctl restart lab-portal.service

# ── collector account: no writable home, no password, not in sudo ──
chown root:root /home/extorq-collector
chmod 0755 /home/extorq-collector
passwd -l extorq-collector >/dev/null 2>&1 || true
if id -nG extorq-collector | tr ' ' '\n' | grep -qx sudo; then
  gpasswd -d extorq-collector sudo
fi
chown root:root /etc/ssh/authorized_keys /etc/ssh/authorized_keys/extorq-collector
chmod 0755 /etc/ssh/authorized_keys
chmod 0644 /etc/ssh/authorized_keys/extorq-collector

# ── PAM: no dynamic MOTD for the collector account ──
# pam_motd runs /etc/update-motd.d/* as root on every session open, which the
# extorq_root_exec audit rule records (~40 execve per collector connection). The
# collector never reads a MOTD, so the two pam_motd lines are skipped for it only.
if ! grep -q 'extorq-collector: skip pam_motd' /etc/pam.d/sshd; then
  sed -i '/^session[[:space:]]\+optional[[:space:]]\+pam_motd.so[[:space:]]\+motd=\/run\/motd.dynamic/i\
# extorq-collector: skip pam_motd (ExtorQ provisioning)\
session [success=2 default=ignore] pam_succeed_if.so quiet user = extorq-collector' /etc/pam.d/sshd
  log "pam_motd skipped for extorq-collector"
fi

# ── sshd: drop-ins readable for posture checks (no secrets in them) ──
chmod 0644 /etc/ssh/sshd_config.d/*.conf
sshd -t
systemctl try-restart ssh.service || true

# ── journald: persistent storage ──
mkdir -p /var/log/journal
systemd-tmpfiles --create --prefix /var/log/journal
journalctl --flush || true

install -d -m 0755 /var/lib/extorq
date -u +%Y-%m-%dT%H:%M:%SZ >/var/lib/extorq/provisioned
chmod 0644 /var/lib/extorq/provisioned
log "provisioning complete"
