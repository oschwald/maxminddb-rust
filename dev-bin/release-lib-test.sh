#!/bin/bash

set -eu -o pipefail

release_test_script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$release_test_script_dir/release-lib.sh"

release_test_dir=$(mktemp -d)
trap 'rm -rf -- "$release_test_dir"' EXIT

fail() {
    echo "release helper test failed: $*" >&2
    exit 1
}

supported_readme="$release_test_dir/supported.md"
printf '%s\n' \
    'maxminddb = "0.29"' \
    'maxminddb = { version = "0.30", features = ["mmap"] }' \
    'maxminddb = { features = ["simdutf8"], version = "0.28" }' \
    'other = { version = "9.99" }' \
    >"$supported_readme"

update_readme_dependency_versions "$supported_readme" "0.31"

[ "$(grep -Fc 'maxminddb = "0.31"' "$supported_readme")" -eq 1 ] ||
    fail "plain dependency was not updated"
[ "$(grep -Ec '^maxminddb = \{.*version = "0.31"' "$supported_readme")" -eq 2 ] ||
    fail "inline-table dependencies were not updated"
grep -Fxq 'other = { version = "9.99" }' "$supported_readme" ||
    fail "an unrelated version was changed"

unsupported_readme="$release_test_dir/unsupported.md"
printf '%s\n' 'maxminddb = { path = "../maxminddb" }' >"$unsupported_readme"
if (update_readme_dependency_versions "$unsupported_readme" "0.31") \
    2>"$release_test_dir/unsupported.err"; then
    fail "an unsupported dependency form was accepted"
fi
grep -Fq 'Not every maxminddb dependency example' "$release_test_dir/unsupported.err" ||
    fail "unsupported dependency form did not produce an actionable error"

mixed_readme="$release_test_dir/mixed.md"
printf '%s\n' \
    'maxminddb = "0.29"' \
    'maxminddb = { path = "../maxminddb" }' \
    >"$mixed_readme"
cp "$mixed_readme" "$release_test_dir/mixed.before"
if (update_readme_dependency_versions "$mixed_readme" "0.31") \
    2>"$release_test_dir/mixed.err"; then
    fail "mixed supported and unsupported dependency forms were accepted"
fi
cmp -s "$release_test_dir/mixed.before" "$mixed_readme" ||
    fail "a failed update partially modified the README"

missing_readme="$release_test_dir/missing.md"
printf '%s\n' 'other = "1.0"' >"$missing_readme"
if (update_readme_dependency_versions "$missing_readme" "0.31") \
    2>"$release_test_dir/missing.err"; then
    fail "a README without maxminddb examples was accepted"
fi
grep -Fq 'Could not find any maxminddb dependency examples' "$release_test_dir/missing.err" ||
    fail "missing dependency examples did not produce an actionable error"
