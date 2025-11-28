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

echo "Running tests..."
cargo test

echo $'\nDiff:'
git diff

echo $'\nRelease notes:'
echo "$notes"

read -r -p "Commit changes and push to origin? [y/N] " should_push

if [ "$should_push" != "y" ]; then
    echo "Aborting"
    git checkout -- Cargo.toml
    exit 1
fi

if [ -n "$(git status --porcelain)" ]; then
    git commit -m "Prepare $tag release" -a
fi

git push

gh release create --target "$(git branch --show-current)" -t "$version" -n "$notes" "$tag"

git push --tags
