#!/bin/bash

set -eu -o pipefail

# Check that we're not on the main branch
current_branch=$(git branch --show-current)
if [ "$current_branch" = "main" ]; then
    echo "Error: Releases should not be done directly on the main branch."
    echo "Please create a release branch and run this script from there."
    exit 1
fi

# Fetch latest changes and check that we're not behind origin/main
echo "Fetching from origin..."
git fetch origin

if ! git merge-base --is-ancestor origin/main HEAD; then
    echo "Error: Current branch is behind origin/main."
    echo "Please merge or rebase with origin/main before releasing."
    exit 1
fi

changelog=$(cat CHANGELOG.md)

# Match: ## X.Y.Z - YYYY-MM-DD
regex='## ([0-9]+\.[0-9]+\.[0-9]+) - ([0-9]{4}-[0-9]{2}-[0-9]{2})'

if [[ ! $changelog =~ $regex ]]; then
    echo "Could not find version/date line in CHANGELOG.md!"
    echo "Expected format: ## X.Y.Z - YYYY-MM-DD"
    exit 1
fi

version="${BASH_REMATCH[1]}"
date="${BASH_REMATCH[2]}"
readme_version="${version%.*}"

update_readme_dependency_versions() {
    local file=$1
    local dependency_version=$2
    local dependency_pattern='^[[:space:]]*maxminddb[[:space:]]*='
    local dependency_count
    local expected_count

    dependency_count=$(grep -Ec "$dependency_pattern" "$file")
    if [ "$dependency_count" -eq 0 ]; then
        echo "Could not find any maxminddb dependency examples in $file!" >&2
        exit 1
    fi

    sed -i -E \
        -e "s/(^[[:space:]]*maxminddb[[:space:]]*=[[:space:]]*\")[0-9]+\.[0-9]+(\")/\1${dependency_version}\2/" \
        -e "/$dependency_pattern/ s/(version[[:space:]]*=[[:space:]]*\")[0-9]+\.[0-9]+(\")/\1${dependency_version}\2/" \
        "$file"

    expected_count=$(grep -Ec \
        "${dependency_pattern}[[:space:]]*(\"${dependency_version}\"|\{.*version[[:space:]]*=[[:space:]]*\"${dependency_version}\")" \
        "$file")
    if [ "$expected_count" -ne "$dependency_count" ]; then
        echo "Not every maxminddb dependency example in $file uses version $dependency_version:" >&2
        grep -nE "$dependency_pattern" "$file" >&2
        exit 1
    fi
}

# Extract release notes (everything between first ## version and next ## version)
notes=$(sed -n '/^## '"$version"'/,/^## [0-9]/p' CHANGELOG.md | sed '1d;$d')

if [[ "$date" != $(date +"%Y-%m-%d") ]]; then
    echo "Release date $date is not today ($(date +"%Y-%m-%d"))!"
    exit 1
fi

tag="v$version"

if [ -n "$(git status --porcelain)" ]; then
    echo "Working directory is not clean." >&2
    exit 1
fi

# Update version in Cargo.toml
current_cargo_version=$(grep -E '^version = "[0-9]+\.[0-9]+\.[0-9]+"' Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/')
if [ "$current_cargo_version" != "$version" ]; then
    echo "Updating Cargo.toml version from $current_cargo_version to $version"
    sed -i "s/^version = \"$current_cargo_version\"/version = \"$version\"/" Cargo.toml
fi

# Update every dependency example and verify none were missed.
echo "Updating README.md dependency versions to $readme_version"
update_readme_dependency_versions README.md "$readme_version"

echo "Running tests..."
cargo test

echo $'\nDiff:'
git diff

echo $'\nRelease notes:'
echo "$notes"

read -r -p "Commit changes and push to origin? [y/N] " should_push

if [ "$should_push" != "y" ]; then
    echo "Aborting"
    git checkout -- Cargo.toml README.md
    exit 1
fi

if [ -n "$(git status --porcelain)" ]; then
    git commit -m "Prepare $tag release" -a
fi

git push

gh release create --target "$(git branch --show-current)" -t "$version" -n "$notes" "$tag"

git push --tags
