#!/usr/bin/env bash

# Copyright (c) Indrajit Roy
#
# This file is licensed under the Affero General Public License version 3 or
# any later version.
#
# See the file LICENSE for details.

function run() {
    echo " ===========> Running ${1} ..."
    echo
    g++ contrib/"${1}".cpp -Ltarget/debug -lrusotp -o target/"${1}".out
    time ./target/"${1}".out
    echo
}

echo " ===========> Building ..."
cargo build
echo

run hotp_fn
run totp_fn