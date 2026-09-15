#!/bin/sh
set -eu

secret_dir=${DEPLOYSEAL_SECRET_DIR:-/etc/deployseal/secrets}

load_secret() {
  name=$1
  file=$2
  [ -r "$secret_dir/$file" ] || { printf '%s\n' "missing AWS secret: $secret_dir/$file" >&2; exit 1; }
  value=$(cat "$secret_dir/$file")
  export "$name=$value"
}

load_secret DEPLOYSEAL_MIDNIGHT_SEED_HEX midnight-seed
load_secret DEPLOYSEAL_MIDNIGHT_PRIVATE_STATE_PASSWORD midnight-password
load_secret DEPLOYSEAL_PRIVATE_POLICY_SALT_HEX policy-salt
load_secret DEPLOYSEAL_POLICY_JSON server-policy-json
load_secret DEPLOYSEAL_EVIDENCE_JSON server-evidence-json
load_secret DEPLOYSEAL_EVIDENCE_FACTS_JSON evidence-facts-json
load_secret DEPLOYSEAL_EVIDENCE_ADAPTER_PUBLIC_KEY evidence-adapter-public-key
load_secret DEPLOYSEAL_BUILD_FACT_JSON build-fact-json
load_secret DEPLOYSEAL_BUILD_ADAPTER_PUBLIC_KEY build-adapter-public-key
load_secret DEPLOYSEAL_MIDNIGHT_CONTRACT_ADDRESS contract-address
load_secret DEPLOYSEAL_API_TOKEN api-token

exec /usr/bin/node /opt/deployseal/server/src/index.js
