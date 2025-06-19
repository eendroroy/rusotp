#!/usr/bin/env bash

function run() {
    echo " ===========> Running ${1} ..."
    echo
    g++ contrib/"${1}".cpp -Ltarget/debug -lrusotp -o target/"${1}".out
    ./target/"${1}".out
    echo
}

echo " ===========> Building ..."
cargo build
echo

run hotp_fn
run totp_fn