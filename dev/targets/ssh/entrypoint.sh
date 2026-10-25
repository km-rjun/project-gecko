#!/bin/sh
set -eu

# Host keys are generated per container: recreating the container yields new host keys,
# which is how host-key mismatch (TOFU) handling is tested.
ssh-keygen -A >/dev/null

if [ -f /dev-keys/devuser_ed25519.pub ]; then
    install -m 600 -o devuser -g devuser /dev-keys/devuser_ed25519.pub /home/devuser/.ssh/authorized_keys
else
    echo "warning: /dev-keys/devuser_ed25519.pub missing; key auth disabled" >&2
fi

echo "host key fingerprints:"
for k in /etc/ssh/ssh_host_*_key.pub; do ssh-keygen -lf "$k"; done

exec /usr/sbin/sshd -D -e
