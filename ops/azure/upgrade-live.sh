#!/bin/sh
set -eu

repo=/opt/deployseal
env_file=/etc/deployseal/server.env
secret_dir=/etc/deployseal/secrets

install -d -o deployseal -g deployseal -m 0750 "$secret_dir" /var/lib/deployseal/midnight
git -c safe.directory="$repo" -C "$repo" pull --ff-only
npm --prefix "$repo/contracts/deployseal" ci
npm --prefix "$repo/server" ci
npm --prefix "$repo/client" ci
npm --prefix "$repo/client" run build
find /var/www/deployseal -mindepth 1 -delete
cp -a "$repo/client/dist/." /var/www/deployseal/

set_env() {
  key=$1
  value=$2
  if grep -q "^$key=" "$env_file"; then
    sed -i "s|^$key=.*|$key=$value|" "$env_file"
  else
    printf '%s=%s\n' "$key" "$value" >>"$env_file"
  fi
}

set_env DEPLOYSEAL_MIDNIGHT_STATE_ID deployseal-private-state-v2
set_env DEPLOYSEAL_MIDNIGHT_DB_PATH /var/lib/deployseal/midnight
set_env DEPLOYSEAL_STATE_PATH /var/lib/deployseal/state.sqlite
set_env DEPLOYSEAL_ALLOW_NEW_OPERATION true
set_env DEPLOYSEAL_CRASH_MODE kill
set_env DEPLOYSEAL_REQUIRE_BUILD_FACT true
set_env DEPLOYSEAL_REQUIRE_OPERATION_ATTESTATION true
set_env DEPLOYSEAL_AZURE_ALLOWED_MEASUREMENTS_FILE /etc/deployseal/allowed-measurements
set_env DEPLOYSEAL_AZURE_ATTESTATION_USER_DATA_FILE /etc/deployseal/attestation.user-data
set_env DEPLOYSEAL_AZURE_ATTESTATION_HELPER /usr/local/bin/deployseal-attest
set_env DEPLOYSEAL_AZURE_ATTESTATION_USE_SUDO true
set_env DEPLOYSEAL_ATTESTATION_MAX_AGE_SECONDS 300
chmod 0640 "$env_file"

az login --identity --allow-no-subscriptions --only-show-errors >/dev/null
for name in contract-address build-fact-json build-adapter-public-key; do
  temporary="$secret_dir/$name.tmp"
  az keyvault secret show --vault-name deploysealkv260912 --name "$name" --query value --output tsv --only-show-errors >"$temporary"
  mv -f "$temporary" "$secret_dir/$name"
done
chown deployseal:deployseal "$secret_dir/contract-address" "$secret_dir/build-fact-json" "$secret_dir/build-adapter-public-key"
chmod 0600 "$secret_dir/contract-address" "$secret_dir/build-fact-json" "$secret_dir/build-adapter-public-key"

cat >/usr/local/bin/deployseal-attest <<'EOF'
#!/bin/sh
set -eu
set -a
. /etc/deployseal/server.env
set +a
install -d -o root -g deployseal -m 0750 /etc/deployseal
temporary=/etc/deployseal/attestation.jwt.tmp
user_data=${1:-$(openssl rand -hex 64)}
case "$user_data" in
  ""|*[!0-9a-f]*) printf '%s\n' 'attestation challenge must be lowercase hex' >&2; exit 2 ;;
esac
[ "${#user_data}" -eq 128 ] || { printf '%s\n' 'attestation challenge must be 64-byte hex' >&2; exit 2; }
printf '%s\n' "$user_data" >/etc/deployseal/attestation.user-data.tmp
chown root:deployseal /etc/deployseal/attestation.user-data.tmp
chmod 0640 /etc/deployseal/attestation.user-data.tmp
for attempt in $(seq 1 12); do
  raw=$(/usr/local/bin/azure-guest-attest tee-attest --endpoint "$DEPLOYSEAL_AZURE_ATTESTATION_ENDPOINT" --user-data "hex:$user_data" 2>>/var/log/deployseal-attestation.log || true)
  token=$(printf '%s' "$raw" | grep -Eo '[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' | tail -n 1 || true)
  if [ -n "$token" ]; then
    printf '%s\n' "$token" >"$temporary"
    chown root:deployseal "$temporary"
    chmod 0640 "$temporary"
    mv -f "$temporary" /etc/deployseal/attestation.jwt
    mv -f /etc/deployseal/attestation.user-data.tmp /etc/deployseal/attestation.user-data
    exit 0
  fi
  sleep 5
done
printf '%s\n' 'Azure SEV-SNP attestation token was not produced' >&2
exit 1
EOF
chmod 0755 /usr/local/bin/deployseal-attest

printf '%s\n' 'deployseal ALL=(root) NOPASSWD: /usr/local/bin/deployseal-attest *' >/etc/sudoers.d/deployseal-attestation
chmod 0440 /etc/sudoers.d/deployseal-attestation
visudo -cf /etc/sudoers.d/deployseal-attestation

cat >/etc/systemd/system/deployseal-attestation.service <<'EOF'
[Unit]
Description=DeploySeal Azure SEV-SNP attestation
After=network-online.target
Wants=network-online.target
Before=deployseal.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/deployseal-attest
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

cat >/usr/local/bin/deployseal-refresh-build-fact <<'EOF'
#!/bin/sh
set -eu
umask 077
az login --identity --allow-no-subscriptions --only-show-errors >/dev/null
changed=0
for name in build-fact-json build-adapter-public-key; do
  temporary="/etc/deployseal/secrets/$name.tmp"
  if ! az keyvault secret show --vault-name deploysealkv260912 --name "$name" --query value --output tsv --only-show-errors >"$temporary" 2>/dev/null; then
    rm -f "$temporary"
    exit 0
  fi
  if ! cmp -s "$temporary" "/etc/deployseal/secrets/$name"; then
    mv -f "$temporary" "/etc/deployseal/secrets/$name"
    chown deployseal:deployseal "/etc/deployseal/secrets/$name"
    chmod 0600 "/etc/deployseal/secrets/$name"
    changed=1
  else
    rm -f "$temporary"
  fi
done
if [ "$changed" -eq 1 ]; then
  systemctl restart deployseal.service
fi
EOF
chmod 0755 /usr/local/bin/deployseal-refresh-build-fact

cat >/etc/systemd/system/deployseal-build-fact-refresh.service <<'EOF'
[Unit]
Description=Refresh the signed DeploySeal BuildFact from Azure Key Vault
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/deployseal-refresh-build-fact
EOF

cat >/etc/systemd/system/deployseal-build-fact-refresh.timer <<'EOF'
[Unit]
Description=Refresh the signed DeploySeal BuildFact periodically

[Timer]
OnBootSec=30s
OnUnitActiveSec=30s
Unit=deployseal-build-fact-refresh.service

[Install]
WantedBy=timers.target
EOF

if ! grep -q '^ExecStartPre=/usr/bin/sudo -n /usr/local/bin/deployseal-attest$' /etc/systemd/system/deployseal.service; then
  sed -i '/^ExecStart=\/usr\/bin\/node \/opt\/deployseal\/server\/src\/azure-start.js$/i ExecStartPre=/usr/bin/sudo -n /usr/local/bin/deployseal-attest' /etc/systemd/system/deployseal.service
fi

chown -R deployseal:deployseal "$repo" /var/lib/deployseal
systemctl daemon-reload
systemctl enable deployseal-attestation.service deployseal.service deployseal-build-fact-refresh.timer
systemctl start deployseal-build-fact-refresh.timer
systemctl restart deployseal-attestation.service
if [ ! -s /etc/deployseal/allowed-measurements ]; then
  node --input-type=module -e "import { readFileSync, writeFileSync } from 'node:fs'; const token=readFileSync('/etc/deployseal/attestation.jwt','utf8').trim(); const payload=JSON.parse(Buffer.from(token.split('.')[1], 'base64url')); const measurement=payload['x-ms-sevsnpvm-launchmeasurement']; if (!measurement) throw new Error('attestation measurement missing'); writeFileSync('/etc/deployseal/allowed-measurements', measurement.toLowerCase()+'\\n', { mode: 0o640 });"
fi
chown root:deployseal /etc/deployseal/allowed-measurements /etc/deployseal/attestation.user-data
chmod 0640 /etc/deployseal/allowed-measurements /etc/deployseal/attestation.user-data
systemctl start deployseal-build-fact-refresh.service
systemctl restart deployseal.service
sleep 2
printf 'repo='; git -c safe.directory="$repo" -C "$repo" rev-parse --short HEAD
printf 'contract='; tr -d '\n' <"$secret_dir/contract-address"; printf '\n'
printf 'broker='; systemctl is-active deployseal.service
printf 'state='; test -s /var/lib/deployseal/state.sqlite && printf 'sqlite\n'
