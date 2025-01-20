#!/usr/bin/env bash

echo "Running tests"
cargo test
echo

echo "Building lib"
cargo build --release
echo

echo "Running examples hotp"
cargo run --example hotp
echo

echo "Running examples totp"
cargo run --example totp
echo

echo "Generating header"
cbindgen --config c_examples/cbindgen.toml --crate rusotp --output c_examples/rusotp.h
echo

echo "Compiling hotp_fn.cpp"
g++ c_examples/hotp_fn.cpp -Ltarget/release -lrusotp -o c_examples/hotp_fn.out
echo

echo "Compiling totp_fn.cpp"
g++ c_examples/totp_fn.cpp -Ltarget/release -lrusotp -o c_examples/totp_fn.out
echo

echo "Running hotp_fn.out"
echo
./c_examples/hotp_fn.out
echo

echo "Running totp_fn.out"
echo
./c_examples/totp_fn.out
echo
