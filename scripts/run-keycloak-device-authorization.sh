#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "$0")/.." && pwd -P)"
container_name="clavenar-keycloak-device-${RANDOM}-${$}"
keycloak_url="${CLAVENAR_KEYCLOAK_URL:-http://127.0.0.1:18081}"
keycloak_image="quay.io/keycloak/keycloak:26.3.2@sha256:98fab020a3a490aba0978f237e2a06cd0ea42bf149c6cf10f11c0aaf27728ff2"
keycloak_port="${keycloak_url##*:}"
read -r -a docker_command <<< "${DOCKER:-docker}"

cleanup() {
    "${docker_command[@]}" rm -f "$container_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

"${docker_command[@]}" run --rm --detach \
  --name "$container_name" \
  --publish "127.0.0.1:${keycloak_port}:8080" \
  --env KC_BOOTSTRAP_ADMIN_USERNAME=admin \
  --env KC_BOOTSTRAP_ADMIN_PASSWORD=device-admin-password \
  --volume "${repo_dir}/tests/keycloak/device-realm.json:/opt/keycloak/data/import/clavenar-device.json:ro" \
  "$keycloak_image" \
  start-dev --import-realm >/dev/null

for _ in $(seq 1 60); do
    if curl --fail --silent --show-error \
      "${keycloak_url}/realms/clavenar-device/.well-known/openid-configuration" \
      >/dev/null; then
        break
    fi
    sleep 1
done
curl --fail --silent --show-error \
  "${keycloak_url}/realms/clavenar-device/.well-known/openid-configuration" \
  >/dev/null

CLAVENAR_KEYCLOAK_URL="$keycloak_url" \
  cargo test --test keycloak_device_authorization -- --ignored --nocapture
