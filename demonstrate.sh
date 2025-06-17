#!/usr/bin/env bash

echo " ===========> Building ..."
cargo build
echo

echo " ===========> Compiling hotp_fn.cpp ..."
g++ contrib/hotp_fn.cpp -Ltarget/debug -lrusotp -o contrib/hotp_fn.out
echo

echo " ===========> Compiling totp_fn.cpp ..."
g++ contrib/totp_fn.cpp -Ltarget/debug -lrusotp -o contrib/totp_fn.out
echo

echo " ===========> Running hotp_fn.out ..."
echo
./contrib/hotp_fn.out
echo

echo " ===========> Running totp_fn.out ..."
echo
./contrib/totp_fn.out
echo
