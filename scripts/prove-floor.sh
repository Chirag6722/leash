#!/usr/bin/env bash
# Prove the floor for every possible request with Cedar's symbolic compiler and cvc5.
#
#   scripts/prove-floor.sh            proves cedar/ (the repo's policies)
#   scripts/prove-floor.sh --live     syncs the deployed policy bucket to a temp dir and proves THAT
#   scripts/prove-floor.sh <dir>      proves any dir holding schema.json, floor.cedar, policies/*.cedar
#
# Builds verify/ (Rust, ~4 min the first time) and downloads cvc5 1.3.1 into .build/ if it is not
# on PATH or in $CVC5. Exit 0: floor holds. Exit 1: an escape was found and printed. Exit 2: setup.
set -euo pipefail
cd "$(dirname "$0")/.."

CVC5_VERSION=1.3.1
BUILD=.build
mkdir -p "$BUILD"

case "$(uname -s)" in
  Linux*)  ASSET="cvc5-Linux-x86_64-static";  BIN="cvc5" ;;
  Darwin*) ASSET="cvc5-macOS-arm64-static";   BIN="cvc5" ;;
  *)       ASSET="cvc5-Win64-x86_64-static";  BIN="cvc5.exe" ;;
esac

if [ -z "${CVC5:-}" ]; then
  if command -v cvc5 >/dev/null 2>&1; then
    CVC5="$(command -v cvc5)"
  else
    if [ ! -x "$BUILD/$ASSET/bin/$BIN" ]; then
      echo "downloading cvc5 $CVC5_VERSION ($ASSET)..." >&2
      curl -sSL -o "$BUILD/$ASSET.zip" "https://github.com/cvc5/cvc5/releases/download/cvc5-$CVC5_VERSION/$ASSET.zip"
      (cd "$BUILD" && unzip -qo "$ASSET.zip")
      chmod +x "$BUILD/$ASSET/bin/$BIN" || true
    fi
    CVC5="$PWD/$BUILD/$ASSET/bin/$BIN"
  fi
fi
export CVC5

if [ ! -x verify/target/release/leash-prove ] && [ ! -x verify/target/release/leash-prove.exe ]; then
  echo "building verify/ (cedar-policy-symcc)..." >&2
  (cd verify && cargo build --release --quiet)
fi
PROVE=verify/target/release/leash-prove
[ -x "$PROVE" ] || PROVE="$PROVE.exe"

TARGET="${1:-cedar}"
if [ "$TARGET" = "--live" ]; then
  STACK="${STACK_NAME:-leash}"
  BUCKET="$(aws cloudformation describe-stacks --stack-name "$STACK" \
    --query "Stacks[0].Outputs[?OutputKey=='PolicyBucketName'].OutputValue" --output text 2>/dev/null || true)"
  if [ -z "$BUCKET" ] || [ "$BUCKET" = "None" ]; then
    BUCKET="$(aws s3api list-buckets --query "Buckets[?starts_with(Name, '$STACK-policies-')].Name | [0]" --output text)"
  fi
  TARGET="$(mktemp -d)"
  echo "syncing s3://$BUCKET/cedar/ -> $TARGET" >&2
  aws s3 sync "s3://$BUCKET/cedar/" "$TARGET" --quiet
  cp cedar/floor.cedar "$TARGET/floor.cedar"   # the floor ships in the repo, never in the bucket
fi

exec "$PROVE" "$TARGET" "${@:2}"
