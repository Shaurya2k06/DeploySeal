#!/usr/bin/env bash
set -Eeuo pipefail

public_host=${1:?usage: secure-live.sh <public-host> <client-origin>}
client_origin=${2:?usage: secure-live.sh <public-host> <client-origin>}
env_file=/etc/deployseal/server.env
secret_dir=/etc/deployseal/secrets
vault_name=${AZURE_KEY_VAULT_NAME:-deploysealkv260912}

case "$public_host" in
  ''|*[!A-Za-z0-9.-]*) printf '%s\n' 'public host must be a DNS hostname' >&2; exit 2 ;;
esac
case "$client_origin" in
  https://[A-Za-z0-9.-]* ) ;;
  * ) printf '%s\n' 'client origin must be an HTTPS origin' >&2; exit 2 ;;
esac
client_origin_host=${client_origin#https://}
case "$client_origin_host" in
  ''|*[!A-Za-z0-9.-]*) printf '%s\n' 'client origin must contain only a DNS hostname' >&2; exit 2 ;;
esac

test -f "$env_file"
test -d /var/www/deployseal
command -v az >/dev/null

apt-get update
apt-get install -y certbot

install -d -o deployseal -g deployseal -m 0750 "$secret_dir"
az login --identity --allow-no-subscriptions --only-show-errors >/dev/null
temporary=$(mktemp /tmp/deployseal-api-token.XXXXXX)
trap 'rm -f "$temporary"' EXIT
az keyvault secret show \
  --vault-name "$vault_name" \
  --name api-token \
  --query value \
  --output tsv \
  --only-show-errors >"$temporary"
test -s "$temporary"
install -o deployseal -g deployseal -m 0600 "$temporary" "$secret_dir/api-token"

set_env() {
  key=$1
  value=$2
  escaped=$(printf '%s' "$value" | sed 's/[&|]/\\&/g')
  if grep -q "^$key=" "$env_file"; then
    sed -i "s|^$key=.*|$key=$escaped|" "$env_file"
  else
    printf '%s=%s\n' "$key" "$value" >>"$env_file"
  fi
}

set_env NODE_ENV production
set_env HOST 127.0.0.1
set_env CLIENT_ORIGIN "$client_origin"
set_env DEPLOYSEAL_REQUIRE_AUTH true
set_env DEPLOYSEAL_REQUIRE_TLS false
set_env DEPLOYSEAL_TLS_TERMINATED true
set_env AZURE_KEY_VAULT_NAME "$vault_name"
chmod 0640 "$env_file"
chown root:deployseal "$env_file"

cat >/etc/nginx/sites-available/deployseal <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name $public_host;
    root /var/www/deployseal;
    index index.html;

    location ^~ /.well-known/acme-challenge/ {
        try_files \$uri =404;
    }

    location / {
        return 308 https://\$host\$request_uri;
    }
}
EOF
nginx -t
systemctl reload nginx

certbot certonly \
  --webroot \
  --webroot-path /var/www/deployseal \
  --domain "$public_host" \
  --non-interactive \
  --agree-tos \
  --register-unsafely-without-email \
  --keep-until-expiring \
  --no-eff-email

cat >/etc/nginx/sites-available/deployseal <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name $public_host;

    location ^~ /.well-known/acme-challenge/ {
        root /var/www/deployseal;
        try_files \$uri =404;
    }

    location / {
        return 308 https://\$host\$request_uri;
    }
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name $public_host;
    root /var/www/deployseal;
    index index.html;

    ssl_certificate /etc/letsencrypt/live/$public_host/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$public_host/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    add_header Strict-Transport-Security \"max-age=31536000\" always;

    location /api/ {
        proxy_pass http://127.0.0.1:8787;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Authorization \$http_authorization;
    }

    location / {
        try_files \$uri \$uri/ /index.html;
    }
}
EOF
nginx -t
systemctl reload nginx

install -d -m 0755 /etc/letsencrypt/renewal-hooks/deploy
cat >/etc/letsencrypt/renewal-hooks/deploy/deployseal-nginx <<'EOF'
#!/bin/sh
set -eu
systemctl reload nginx
EOF
chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/deployseal-nginx

systemctl restart deployseal.service
printf '%s\n' "secured $public_host with Azure Key Vault bearer auth and HTTPS termination"
