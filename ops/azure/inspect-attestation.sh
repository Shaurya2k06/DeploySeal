#!/bin/sh
set -eu

challenge=$(printf '11%.0s' 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 61 62 63 64)
claims=$(sudo /usr/local/bin/azure-guest-attest cvm-report --user-data "$challenge" --claims 2>/dev/null || true)
raw=$(sudo /usr/local/bin/azure-guest-attest tee-attest \
  --endpoint 'https://deploysealmaa260912.eus.attest.azure.net/attest/SevSnpVm?api-version=2022-08-01' \
  --user-data "hex:$challenge" 2>/dev/null)
token=$(printf '%s' "$raw" | grep -Eo '[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' | tail -n 1)
TOKEN="$token" CHALLENGE="$challenge" CLAIMS="$claims" node --input-type=module -e '
  import { createHash } from "node:crypto"
  const payload = JSON.parse(Buffer.from(process.env.TOKEN.split(".")[1], "base64url"))
  const reportData = payload["x-ms-sevsnpvm-reportdata"] || ""
  const challenge = process.env.CHALLENGE
  const hash = (value) => createHash("sha256").update(value).digest("hex")
  const challengeHash = hash(challenge)
  const claims = process.env.CLAIMS
  let cvmClaims = {}
  try { cvmClaims = JSON.parse(claims) } catch {}
  const runtime = payload["x-ms-runtime"] || {}
  console.log(JSON.stringify({
    challengeLength: challenge.length,
    reportDataLength: reportData.length,
    exact: reportData === challenge,
    prefix: reportData.startsWith(challenge),
    firstHalfIsChallengeHash: reportData.slice(0, 64) === challengeHash,
    challengeHash,
    reportDataPrefixHash: hash(reportData.slice(0, 64)),
    reportData,
    cvmClaimKeys: Object.keys(cvmClaims),
    cvmUserData: cvmClaims["user-data"] || cvmClaims["x-ms-sevsnpvm-reportdata"] || null,
    runtimeKeys: Object.keys(runtime),
    runtimeUserData: runtime["user-data"] || null,
    reportDataHash: hash(reportData),
  }))
' 
