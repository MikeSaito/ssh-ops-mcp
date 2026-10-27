#!/bin/sh
set -eu
umask 077
mkdir -p /fixture /home/synthetic/.ssh
ssh-keygen -q -t ed25519 -N '' -f /fixture/host
ssh-keygen -q -t rsa -b 2048 -m PEM -N '' -f /fixture/client
ssh-keygen -q -t rsa -b 2048 -m PEM -N synthetic-fixture-passphrase -f /fixture/client-locked
cat /fixture/client.pub /fixture/client-locked.pub > /home/synthetic/.ssh/authorized_keys
chown -R synthetic:synthetic /home/synthetic
if [ "$1" = dropbear ]; then
    dropbearconvert openssh dropbear /fixture/host /fixture/dropbear-host
    exec dropbear -F -E -r /fixture/dropbear-host -p 22
fi
cat > /fixture/sshd_config <<'CONFIG'
Port 22
ListenAddress 0.0.0.0
HostKey /fixture/host
PidFile /fixture/sshd.pid
PasswordAuthentication yes
PubkeyAuthentication yes
PermitRootLogin no
AllowUsers synthetic
AllowTcpForwarding yes
AllowAgentForwarding no
X11Forwarding no
UsePAM no
PrintMotd no
Subsystem sftp /usr/lib/openssh/sftp-server
CONFIG
if [ "$1" = nosftp ]; then
    sed -i 's|Subsystem sftp .*|Subsystem sftp /nonexistent-synthetic-subsystem|' /fixture/sshd_config
fi
exec /usr/sbin/sshd -D -e -f /fixture/sshd_config
