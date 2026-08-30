update_readme_dependency_versions() {
    local file=$1
    local dependency_version=$2
    local dependency_pattern='^[[:space:]]*maxminddb[[:space:]]*='
    local dependency_count
    local expected_count
    local supported_count
    local temporary_file

    # grep reports status 1 for a valid search with no matches. Preserve its
    # count so the explicit checks below can emit useful release diagnostics.
    dependency_count=$(grep -Ec "$dependency_pattern" "$file" || true)
    if [ "$dependency_count" -eq 0 ]; then
        echo "Could not find any maxminddb dependency examples in $file!" >&2
        return 1
    fi

    supported_count=$(grep -Ec \
        "${dependency_pattern}[[:space:]]*(\"[0-9]+\.[0-9]+\"|\{[^}]*version[[:space:]]*=[[:space:]]*\"[0-9]+\.[0-9]+\")" \
        "$file" || true)
    if [ "$supported_count" -ne "$dependency_count" ]; then
        echo "Not every maxminddb dependency example in $file uses a supported version form:" >&2
        grep -nE "$dependency_pattern" "$file" >&2
        return 1
    fi

    temporary_file=$(mktemp "${file}.tmp.XXXXXX") || return 1
    if ! cp -p -- "$file" "$temporary_file"; then
        rm -f -- "$temporary_file"
        return 1
    fi

    if ! sed -i -E \
        -e "s/(^[[:space:]]*maxminddb[[:space:]]*=[[:space:]]*\")[0-9]+\.[0-9]+(\")/\1${dependency_version}\2/" \
        -e "/$dependency_pattern/ s/(version[[:space:]]*=[[:space:]]*\")[0-9]+\.[0-9]+(\")/\1${dependency_version}\2/" \
        "$temporary_file"; then
        rm -f -- "$temporary_file"
        return 1
    fi

    expected_count=$(grep -Ec \
        "${dependency_pattern}[[:space:]]*(\"${dependency_version}\"|\{.*version[[:space:]]*=[[:space:]]*\"${dependency_version}\")" \
        "$temporary_file" || true)
    if [ "$expected_count" -ne "$dependency_count" ]; then
        echo "Not every maxminddb dependency example in $file uses version $dependency_version:" >&2
        grep -nE "$dependency_pattern" "$temporary_file" >&2
        rm -f -- "$temporary_file"
        return 1
    fi

    if ! mv -- "$temporary_file" "$file"; then
        rm -f -- "$temporary_file"
        return 1
    fi
}
