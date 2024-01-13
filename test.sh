#!/usr/bin/env bash
set -euo pipefail
find src -name "test.json" | while read -r path; do
	name="$(basename "$(realpath -m "$path/..")")"
	"$1" test "$name"
done
