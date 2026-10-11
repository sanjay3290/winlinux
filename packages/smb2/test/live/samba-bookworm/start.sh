# Writes smb.conf with a plain and an encrypted share, adds the test-only
# account and runs smbd in the foreground. EXTRA_GLOBAL adds [global] lines.
set -e
mkdir -p /srv/plain /srv/enc
useradd -M testuser 2>/dev/null || true
chown testuser /srv/plain /srv/enc
cat > /etc/samba/smb.conf <<CONF
[global]
  workgroup = WORKGROUP
  server role = standalone server
  map to guest = never
  server min protocol = SMB2_02
  ${EXTRA_GLOBAL:-}
[plain]
  path = /srv/plain
  read only = no
  valid users = testuser
[enc]
  path = /srv/enc
  read only = no
  valid users = testuser
  smb encrypt = required
CONF
printf 'testpass123\ntestpass123\n' | smbpasswd -a -s testuser >/dev/null
exec smbd --foreground --no-process-group --debug-stdout -d 1
