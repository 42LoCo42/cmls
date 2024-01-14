#!/usr/bin/env bash
set -euo pipefail
vf=()
if [ -n "${2-}" ]; then
	vf=(valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes)
fi
find src -name "test.json" | while read -r path; do
	name="$(basename "$(realpath -m "$path/..")")"
	"${vf[@]}" "$1" test "$name"
done
