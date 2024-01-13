#!/usr/bin/env bash
set -euo pipefail
find src -name test | while read -r path; do
	name="$(basename "$(realpath -m "$path/..")")"
	bash "$path" | "$1" test "$name"
done
