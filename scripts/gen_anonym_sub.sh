#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/gen_anonym_sub.sh --ca-key anonym_ca.key --ca-cert anonym_ca.pem \
    --out-key anonym_sub.key --out-cert anonym_sub.pem [--days 365] [--name NAME]

Generates an Ed25519 anonym delegated signing key and a CA-signed X.509
certificate for yumed --anonym-sub-key/--anonym-sub-cert.
EOF
}

ca_key=""
ca_cert=""
out_key="anonym_sub.key"
out_cert="anonym_sub.pem"
days="365"
name="YUME anonym delegated signer"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ca-key)
      ca_key="${2:-}"
      shift 2
      ;;
    --ca-cert)
      ca_cert="${2:-}"
      shift 2
      ;;
    --out-key)
      out_key="${2:-}"
      shift 2
      ;;
    --out-cert)
      out_cert="${2:-}"
      shift 2
      ;;
    --days)
      days="${2:-}"
      shift 2
      ;;
    --name)
      name="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "${ca_key}" || -z "${ca_cert}" ]]; then
  echo "--ca-key and --ca-cert are required" >&2
  usage >&2
  exit 2
fi
if [[ ! -r "${ca_key}" ]]; then
  echo "CA key is not readable: ${ca_key}" >&2
  exit 1
fi
if [[ ! -r "${ca_cert}" ]]; then
  echo "CA cert is not readable: ${ca_cert}" >&2
  exit 1
fi
if [[ ! "${days}" =~ ^[0-9]+$ || "${days}" == "0" ]]; then
  echo "--days must be a positive integer" >&2
  exit 2
fi

umask 077
tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/yume-anonym-sub.XXXXXX")"
trap 'rm -rf "${tmp_dir}"' EXIT

csr="${tmp_dir}/anonym_sub.csr"
ext="${tmp_dir}/anonym_sub.ext"
serial="0x$(openssl rand -hex 16)"

openssl genpkey -algorithm Ed25519 -out "${out_key}"
openssl req -new -key "${out_key}" -out "${csr}" -subj "/CN=${name}"

cat > "${ext}" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF

openssl x509 -req \
  -in "${csr}" \
  -CA "${ca_cert}" \
  -CAkey "${ca_key}" \
  -set_serial "${serial}" \
  -days "${days}" \
  -extfile "${ext}" \
  -out "${out_cert}"

chmod 600 "${out_key}"

openssl verify -CAfile "${ca_cert}" "${out_cert}" >/dev/null

echo "wrote ${out_key}"
echo "wrote ${out_cert}"
echo
echo "server:"
echo "  yumed --anonym --anonym-proof-mode local --anonym-sub-key ${out_key} --anonym-sub-cert ${out_cert} ..."
echo
echo "client:"
echo "  yume --require-anonym --anonym-ca-cert ${ca_cert} ..."
