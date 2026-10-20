#!/usr/bin/env bash
try_root() {
    echo "${XDG_CACHE_HOME:-$HOME/.cache}/mahi-try"
}

mahi_binary() {
    local target
    target=$(cargo metadata --locked --format-version 1 --no-deps | grep -o '"target_directory":"[^"]*"' | cut -d '"' -f 4)
    echo "$target/debug/mahi"
}

check_binary() {
    if [ ! -x "$1" ]; then
        echo "cannot find the mahi binary at $1" >&2
        exit 1
    fi
}

make_project() {
    local dir=$1 url=$2 made="$1.making"
    if [ -e "$dir" ]; then
        echo "$dir is in the way; run just try-reset first" >&2
        exit 1
    fi
    rm -rf "$made"
    if [ -n "$url" ]; then
        git clone -q "$url" "$made"
    else
        git init -q "$made"
    fi
    if ! git -C "$made" rev-parse -q --verify HEAD > /dev/null; then
        git -C "$made" symbolic-ref HEAD refs/heads/main
        git -C "$made" -c user.name=mahi -c user.email=try@mahi.social -c commit.gpgsign=false \
            commit -q --allow-empty -m init
        if [ -n "$url" ]; then
            git -C "$made" push -q origin HEAD:refs/heads/main
        fi
    fi
    mv "$made" "$dir"
}

check_origin() {
    local dir=$1 url=$2
    if [ -n "$url" ] && [ "$(git -C "$dir" config --get remote.origin.url)" != "$url" ]; then
        echo "$dir does not have $url as origin; run just try-reset first" >&2
        exit 1
    fi
}

https_url() {
    local rest host path
    if [[ $1 == ssh://*/* ]]; then
        rest=${1#ssh://}
        host=${rest%%/*}
        path=${rest#*/}
        host=${host%%:*}
    elif [[ $1 != *://* && $1 == ?*:?* ]]; then
        host=${1%%:*}
        path=${1#*:}
    else
        echo "MAHI_TRY_REMOTE must be an SSH URL, such as git@github.com:me/mahi-test.git" >&2
        exit 1
    fi
    echo "https://${host##*@}/$path"
}

choose_origin() {
    if "$@" remote | grep -q "not pushed; choose"; then
        "$@" remote origin --private
    fi
}

url_host() {
    local host=${1#https://}
    echo "${host%%/*}"
}

credential_name() {
    local host
    host=$(url_host "$1" | tr '[:upper:]' '[:lower:]')
    host=${host//-/--}
    echo "https-${host//./-}"
}
