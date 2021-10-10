#!/usr/bin/env bash
# shellcheck disable=SC2154
# these top lines are moved during build

#openssl public key for verification of updates
read -r PUBKEY << EOF
LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF3Z25kcnk2WGJpNE8wR2w1T2UzSQp1eWRyMlZqR1hteDJFM0thd0wrK1F3a2FVT0RHOEVuT24weFZ1S1ZkZEphZjY3Rmxzd3pPYjh1RFRDTjdsWURnCnFKQXdmNllTOUFsdU5RRmlFQWhFRlgxL0dsMi9TSnFHYXhFVU9HTlV3NTI5a3BVR0MwNmN6SHhENEcvdWNBQlkKT05iWm9Vc1pIYmRnZUNueWs1dzZ0SWs3MEplNmZ2em5Da2JxbUZhS0UyQnhWTERLU0liSDBTak5XT3RSMmF6ZAp1V3p2RU1kVXFlZlZjYXErUDFjV0dLNy94VllSNkV3ME1aQTdWU0xkREhlRUVySW9Kc3UvM2VaeUR5ZDlaUlJvCmdpajM2R1N2SFREclU1ZVdXRlN0Q01UM29DRDhMSjVpbXBReWpWd3Z5M3Z4ZVNVYzVkdytZUDU0OU9jNHF2bzYKOXdJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==
EOF

# Update/Upgrade
# shellcheck disable=SC2120
upgrade() {
  if ${pkg_release}; then
    printf "\033[31mError: Unknown option '%s'.\033[m\n\n" "${1}"
    help
    exit 1
  fi
  umask 027
  TMP_FILE=$(mktemp /tmp/checksec.XXXXXXXXXX)
  SIG_FILE=$(mktemp /tmp/checksec_sig.XXXXXXXX)
  PUBKEY_FILE=$(mktemp /tmp/checksec_pubkey.XXXXXXXXXX)
  fetch "${SCRIPT_URL}" "${TMP_FILE}"
  fetch "${SIG_URL}" "${SIG_FILE}"
  echo "${PUBKEY}" | base64 -d > "${PUBKEY_FILE}"
  if ! openssl dgst -sha256 -verify "${PUBKEY_FILE}" -signature "${SIG_FILE}" "${TMP_FILE}" > /dev/null 2>&1; then
    echo "file signature does not match. Update may be tampered"
    rm -f "${TMP_FILE}" "${SIG_FILE}" "${PUBKEY_FILE}" > /dev/null 2>&1
    exit 1
  fi
  UPDATE_VERSION=$(grep "^SCRIPT_VERSION" "${TMP_FILE}" | awk -F"=" '{ print $2 }')
  if [[ "${SCRIPT_VERSION}" != "${UPDATE_VERSION}" ]]; then
    PERMS=$(stat -c "%a" "$0")
    rm -f "${SIG_FILE}" "${PUBKEY_FILE}" > /dev/null 2>&1
    mv "${TMP_FILE}" "$0" > /dev/null 2>&1
    exit_status=$?
    if [[ "${exit_status}" -eq "0" ]]; then
      echo "checksec.sh updated - Rev. ${UPDATE_VERSION}"
      chmod "${PERMS}" "${0}"
    else
      echo "Error: Could not update... Please check permissions"
      rm -f "${TMP_FILE}" > /dev/null 2>&1
      exit 1
    fi
  else
    echo "checksec.sh not updated... Already on latest version"
    rm -f "${TMP_FILE}" "${SIG_FILE}" "${PUBKEY_FILE}" > /dev/null 2>&1
    exit 1
  fi
  exit 0
}

# Version compare
vercomp() {
  if [[ "${1}" == "${2}" ]]; then
    return 0
  fi
  local IFS=.
  local i ver1="${1}" ver2="${2}"
  # fill empty fields in ver1 with zeros
  for ((i = ${#ver1[@]}; i < ${#ver2[@]}; i++)); do
    ver1[i]=0
  done
  for ((i = 0; i < ${#ver1[@]}; i++)); do
    if [[ -z ${ver2[i]} ]]; then
      # fill empty fields in ver2 with zeros
      ver2[i]=0
    fi
    if ((10#${ver1[i]} > 10#${ver2[i]})); then
      return 1
    fi
    if ((10#${ver1[i]} < 10#${ver2[i]})); then
      return 2
    fi
  done
  return 0
}

# Fetch the update
fetch() {
  if type wget > /dev/null 2>&1; then
    wget --no-check-certificate -O "${2}" "${1}" > /dev/null 2>&1
  elif type curl > /dev/null 2>&1; then
    curl --insecure --remote-name -o "${2}" "${1}" > /dev/null 2>&1
  else
    echo 'Warning: Neither wget nor curl is available. online updates unavailable' >&2
    exit 1
  fi
}
