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

run totp_generate
run totp_verify
run totp_generate_at
run totp_verify_at
run totp_provisioning_uri

echo
echo

run hotp_generate
run hotp_provisioning_uri
run hotp_verify

echo
echo

run hotp_fn
run totp_fn