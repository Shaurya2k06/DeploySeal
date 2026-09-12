#!/usr/bin/env bash
set -Eeuo pipefail

exec > >(tee -a /var/log/deployseal-bootstrap.log) 2>&1
export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y ca-certificates curl git build-essential pkg-config libssl-dev openssl tpm2-tools docker.io nginx sudo
curl -fsSL https://deb.nodesource.com/setup_24.x | bash -
apt-get install -y nodejs
curl -fsSL https://aka.ms/InstallAzureCLIDeb | bash

install -d -o deployseal -g deployseal -m 0750 /opt/deployseal /etc/deployseal/secrets /var/lib/deployseal/midnight
if [ ! -d /opt/deployseal/.git ]; then
  git clone --depth 1 https://github.com/Shaurya2k06/DeploySeal.git /opt/deployseal
else
  git -c safe.directory=/opt/deployseal -C /opt/deployseal pull --ff-only
fi
npm --prefix /opt/deployseal/contracts/deployseal install
npm --prefix /opt/deployseal/server install
npm --prefix /opt/deployseal/client install
npm --prefix /opt/deployseal/client run build

install -d -m 0755 /var/www/deployseal
find /var/www/deployseal -mindepth 1 -delete
cp -a /opt/deployseal/client/dist/. /var/www/deployseal/
cat >/etc/nginx/sites-available/deployseal <<'EOF'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    root /var/www/deployseal;
    index index.html;

    location /api/ {
        proxy_pass http://127.0.0.1:8787;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location / {
        try_files $uri $uri/ /index.html;
    }
}
EOF
ln -sf /etc/nginx/sites-available/deployseal /etc/nginx/sites-enabled/deployseal
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl enable --now nginx

if [ ! -x /usr/local/bin/azure-guest-attest ]; then
  export PATH="/root/.cargo/bin:$PATH"
  if [ ! -x /root/.cargo/bin/cargo ]; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
  fi
  if [ ! -d /opt/azure-guest-attestation-sdk/.git ]; then
    git clone --depth 1 https://github.com/Azure/azure-guest-attestation-sdk.git /opt/azure-guest-attestation-sdk
  fi
  cargo build --manifest-path /opt/azure-guest-attestation-sdk/Cargo.toml --release -p azure-guest-attest
  install -o root -g root -m 0755 /opt/azure-guest-attestation-sdk/target/release/azure-guest-attest /usr/local/bin/azure-guest-attest
fi

cat >/etc/deployseal/server.env <<'EOF'
DEPLOYSEAL_PROVIDER=azure-arm
AZURE_SUBSCRIPTION_ID=9b6559f4-2b0a-4e2a-8f77-b1f72d8310d8
DEPLOYSEAL_AZURE_RESOURCE_GROUP=deployseal-target-rg
DEPLOYSEAL_AZURE_LOCATION=eastus
DEPLOYSEAL_AZURE_TARGET=deployseal-azure-demo
AZURE_KEY_VAULT_URL=https://deploysealkv260912.vault.azure.net
DEPLOYSEAL_AZURE_KEY_NAME=deployseal-receipt
DEPLOYSEAL_AZURE_KEY_ALGORITHM=PS256
DEPLOYSEAL_AZURE_ATTESTATION_ENDPOINT=https://deploysealmaa260912.eus.attest.azure.net/attest/SevSnpVm?api-version=2022-08-01
DEPLOYSEAL_AZURE_ATTESTATION_TOKEN_FILE=/etc/deployseal/attestation.jwt
DEPLOYSEAL_AZURE_ALLOWED_MEASUREMENTS_FILE=/etc/deployseal/allowed-measurements
DEPLOYSEAL_AZURE_ATTESTATION_USER_DATA_FILE=/etc/deployseal/attestation.user-data
DEPLOYSEAL_AZURE_ATTESTATION_HELPER=/usr/local/bin/deployseal-attest
DEPLOYSEAL_AZURE_ATTESTATION_USE_SUDO=true
DEPLOYSEAL_ATTESTATION_MAX_AGE_SECONDS=300
DEPLOYSEAL_REQUIRE_BUILD_FACT=true
DEPLOYSEAL_REQUIRE_OPERATION_ATTESTATION=true
DEPLOYSEAL_AZURE_SECRET_DIR=/etc/deployseal/secrets
DEPLOYSEAL_MIDNIGHT_PROOF=http://127.0.0.1:6300
DEPLOYSEAL_MIDNIGHT_STATE_ID=deployseal-private-state-v2
DEPLOYSEAL_MIDNIGHT_DB_PATH=/var/lib/deployseal/midnight
DEPLOYSEAL_STATE_PATH=/var/lib/deployseal/state.sqlite
DEPLOYSEAL_ALLOW_NEW_OPERATION=true
DEPLOYSEAL_CRASH_MODE=kill
HOST=0.0.0.0
PORT=8787
CLIENT_ORIGIN=*
EOF
chmod 0640 /etc/deployseal/server.env

az login --identity --allow-no-subscriptions --only-show-errors >/dev/null
get_secret() {
  local name="$1"
  local value
  for _ in $(seq 1 120); do
    if value=$(az keyvault secret show --vault-name deploysealkv260912 --name "$name" --query value --output tsv --only-show-errors 2>/dev/null); then
      printf '%s' "$value"
      return 0
    fi
    sleep 5
  done
  return 1
}

umask 077
for name in midnight-seed midnight-password policy-salt policy-json server-policy-json server-evidence-json contract-address build-fact-json build-adapter-public-key; do
  get_secret "$name" >/etc/deployseal/secrets/$name
done
chown -R deployseal:deployseal /etc/deployseal/secrets
chmod 0600 /etc/deployseal/secrets/*

cat >/usr/local/bin/deployseal-attest <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
set -a
source /etc/deployseal/server.env
set +a
install -d -o root -g deployseal -m 0750 /etc/deployseal
temporary=/etc/deployseal/attestation.jwt.tmp
user_data=${1:-$(openssl rand -hex 64)}
if [[ ! "$user_data" =~ ^[0-9a-f]{128}$ ]]; then
  printf '%s\n' 'attestation challenge must be 64-byte lowercase hex' >&2
  exit 2
fi
printf '%s\n' "$user_data" >/etc/deployseal/attestation.user-data.tmp
chown root:deployseal /etc/deployseal/attestation.user-data.tmp
chmod 0640 /etc/deployseal/attestation.user-data.tmp
for _ in $(seq 1 12); do
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

cat >/etc/sudoers.d/deployseal-attestation <<'EOF'
deployseal ALL=(root) NOPASSWD: /usr/local/bin/deployseal-attest *
EOF
chmod 0440 /etc/sudoers.d/deployseal-attestation
visudo -cf /etc/sudoers.d/deployseal-attestation

cat >/etc/systemd/system/deployseal-proof.service <<'EOF'
[Unit]
Description=DeploySeal Midnight proof server
After=docker.service network-online.target
Wants=docker.service network-online.target

[Service]
Type=simple
Restart=always
RestartSec=5
ExecStartPre=-/usr/bin/docker rm -f deployseal-proof
ExecStart=/usr/bin/docker run --rm --name deployseal-proof -p 6300:6300 midnightntwrk/proof-server:8.1.0 midnight-proof-server -v
ExecStop=/usr/bin/docker stop -t 10 deployseal-proof

[Install]
WantedBy=multi-user.target
EOF

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
#!/usr/bin/env bash
set -Eeuo pipefail
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

cat >/etc/systemd/system/deployseal.service <<'EOF'
[Unit]
Description=DeploySeal Azure confidential release broker
Requires=deployseal-proof.service deployseal-attestation.service
After=deployseal-proof.service deployseal-attestation.service

[Service]
Type=simple
User=deployseal
WorkingDirectory=/opt/deployseal
EnvironmentFile=/etc/deployseal/server.env
ExecStartPre=/usr/bin/sudo -n /usr/local/bin/deployseal-attest
ExecStart=/usr/bin/node /opt/deployseal/server/src/azure-start.js
Restart=always
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

chown -R deployseal:deployseal /opt/deployseal /var/lib/deployseal
systemctl daemon-reload
systemctl enable --now deployseal-proof.service
systemctl enable deployseal-attestation.service deployseal.service deployseal-build-fact-refresh.timer
systemctl start deployseal-build-fact-refresh.timer
systemctl restart deployseal-attestation.service
if [ ! -s /etc/deployseal/allowed-measurements ]; then
  node --input-type=module -e "import { readFileSync, writeFileSync } from 'node:fs'; const token=readFileSync('/etc/deployseal/attestation.jwt','utf8').trim(); const p=JSON.parse(Buffer.from(token.split('.')[1], 'base64url')); const m=p['x-ms-sevsnpvm-launchmeasurement']; if (!m) throw new Error('attestation measurement missing'); writeFileSync('/etc/deployseal/allowed-measurements', m.toLowerCase()+'\n', { mode: 0o640 });"
fi
chown root:deployseal /etc/deployseal/allowed-measurements
chmod 0640 /etc/deployseal/allowed-measurements
systemctl start deployseal-build-fact-refresh.service
systemctl start deployseal.service
