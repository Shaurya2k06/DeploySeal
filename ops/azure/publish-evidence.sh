#!/usr/bin/env bash
set -Eeuo pipefail

bundle=${1:?usage: publish-evidence.sh <bundle.json> <public-keys.json> <scope.json>}
public_keys=${2:?usage: publish-evidence.sh <bundle.json> <public-keys.json> <scope.json>}
scope=${3:?usage: publish-evidence.sh <bundle.json> <public-keys.json> <scope.json>}
vault_name=${AZURE_KEY_VAULT_NAME:-deploysealkv260912}
repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

node "$repo/server/src/verify-evidence.js" "$bundle" "$public_keys" "$scope" >/dev/null
az keyvault secret set --vault-name "$vault_name" --name evidence-facts-json --file "$bundle" --only-show-errors >/dev/null
az keyvault secret set --vault-name "$vault_name" --name evidence-adapter-public-key --file "$public_keys" --only-show-errors >/dev/null
printf '%s\n' "published verified EvidenceFacts to $vault_name"
