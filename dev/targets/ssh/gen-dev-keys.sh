#!/bin/sh
set -eu
key=/out/devuser_ed25519
owner=$(stat -c '%u:%g' /out)
if [ ! -f "$key" ]; then
    ssh-keygen -q -t ed25519 -N '' -C devuser@test-ssh-target -f "$key"
    echo "generated $key"
else
    echo "$key exists, keeping it"
fi
chown "$owner" "$key" "$key.pub"
chmod 600 "$key"
chmod 644 "$key.pub"
