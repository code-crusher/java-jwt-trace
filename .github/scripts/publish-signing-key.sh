#!/usr/bin/env bash
#
# Publishes the release signing key to keys.openpgp.org.
#
# Users verify the signatures on the artifacts published to Maven Central with
# tools such as pgpverify-maven-plugin, which look the signing key up on
# keys.openpgp.org. That keyserver only accepts uploads through its VKS API, so
# `gpg --send-keys` and `curl -T` do not work against it. Without this step a
# release can be signed correctly and still be unverifiable because the key was
# never published (see https://github.com/auth0/java-jwt/issues/791).
#
# A key is retrievable by fingerprint or key ID as soon as it is uploaded.
# Verifying its user IDs by email is a separate, optional step that only
# affects lookups by email address, so it is not required to verify signatures.
#
set -euo pipefail

DEFAULT_KEYSERVER="https://keys.openpgp.org"
UPLOAD_ATTEMPTS=3

key_file=""
fingerprint=""
timeout=60
retry_delay=2
keyserver="$DEFAULT_KEYSERVER"

usage() {
    cat <<EOF
Usage: $(basename "$0") [options]

Publishes an OpenPGP public key to keys.openpgp.org and verifies that it is
retrievable by fingerprint.

Options:
  --key-file PATH      Armored public key to publish. When omitted, the public
                       key is exported from the private key in \$SIGNING_KEY.
  --fingerprint FPR    Fingerprint of the key to publish. When omitted, it is
                       read from the key file or from \$SIGNING_KEY.
  --keyserver URL      Base URL of the keyserver.
                       Default: $DEFAULT_KEYSERVER
  --timeout SECONDS    How long to wait for the key to become retrievable.
                       Default: $timeout
  --retry-delay SECONDS
                       Delay between retries. Default: $retry_delay
  -h, --help           Show this help.
EOF
}

fail() {
    echo "error: $*" >&2
    exit 1
}

while [ $# -gt 0 ]; do
    case "$1" in
        --key-file)
            key_file="${2:-}"
            shift 2
            ;;
        --fingerprint)
            fingerprint="${2:-}"
            shift 2
            ;;
        --keyserver)
            keyserver="${2:-}"
            shift 2
            ;;
        --timeout)
            timeout="${2:-}"
            shift 2
            ;;
        --retry-delay)
            retry_delay="${2:-}"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage >&2
            fail "unknown option: $1"
            ;;
    esac
done

command -v curl >/dev/null 2>&1 || fail "curl is required"
command -v jq >/dev/null 2>&1 || fail "jq is required"

work_dir="$(mktemp -d)"
cleanup() {
    rm -rf "$work_dir"
}
trap cleanup EXIT

if [ -z "$key_file" ]; then
    [ -n "${SIGNING_KEY:-}" ] || fail "provide --key-file or set SIGNING_KEY"
    command -v gpg >/dev/null 2>&1 || fail "gpg is required to read SIGNING_KEY"

    # Import into an ephemeral keyring so the runner's default keyring is never
    # touched. Importing a private key does not require its passphrase.
    export GNUPGHOME="$work_dir/gnupg"
    mkdir -p "$GNUPGHOME"
    chmod 700 "$GNUPGHOME"

    printf '%s' "$SIGNING_KEY" | gpg --batch --quiet --import \
        || fail "could not import the key in SIGNING_KEY"

    if [ -z "$fingerprint" ]; then
        fingerprint="$(gpg --batch --list-keys --with-colons \
            | awk -F: '$1 == "fpr" { print $10; exit }')"
    fi
    [ -n "$fingerprint" ] || fail "could not determine the signing key fingerprint"

    key_file="$work_dir/public-key.asc"
    gpg --batch --armor --export "$fingerprint" > "$key_file" \
        || fail "could not export the public key for $fingerprint"
elif [ -z "$fingerprint" ]; then
    command -v gpg >/dev/null 2>&1 || fail "gpg is required to read the key fingerprint"
    [ -f "$key_file" ] || fail "key file not found: $key_file"
    fingerprint="$(gpg --batch --show-keys --with-colons "$key_file" 2>/dev/null \
        | awk -F: '$1 == "fpr" { print $10; exit }')" || true
    [ -n "$fingerprint" ] || fail "could not read a key fingerprint from $key_file"
fi

payload="$work_dir/payload.json"
jq -Rs '{keytext: .}' < "$key_file" > "$payload" \
    || fail "could not build the upload payload"

upload_url="${keyserver%/}/vks/v1/upload"
echo "Uploading $fingerprint to $upload_url"

attempt=1
while [ "$attempt" -le "$UPLOAD_ATTEMPTS" ]; do
    if curl --silent --show-error --fail \
        --header 'Content-Type: application/json' \
        --data "@$payload" \
        "$upload_url"; then
        break
    fi

    if [ "$attempt" -eq "$UPLOAD_ATTEMPTS" ]; then
        fail "could not upload the signing key to $upload_url"
    fi

    echo "Upload attempt $attempt failed, retrying in ${retry_delay}s" >&2
    attempt=$((attempt + 1))
    sleep "$retry_delay"
done

# Uploads are processed synchronously, but confirm the key is actually
# retrievable before any artifact is published. Failing the release here is
# preferable to shipping artifacts whose signatures cannot be verified.
lookup_url="${keyserver%/}/vks/v1/by-fingerprint/$fingerprint"
deadline=$(( $(date +%s) + timeout ))
until curl --silent --show-error --fail --output /dev/null "$lookup_url"; do
    if [ "$(date +%s)" -ge "$deadline" ]; then
        fail "signing key $fingerprint is not retrievable from $lookup_url"
    fi
    sleep "$retry_delay"
done

echo "Signing key $fingerprint is retrievable from $lookup_url"
