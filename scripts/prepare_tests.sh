#!/bin/bash

export RUSTFLAGS="-Zprofile -C force-frame-pointers --cfg dyncov"
export PROFILE="fuzz"
export SODIUM_USE_PKG_CONFIG=1
export BISECT_FILE=/tezos/_coverage_output/
export TEZOS_BASE_DIR=/tezos
export OCAML_BUILD_CHAIN=local

mkdir -p /coverage/develop/.fuzzing.latest/operation_fuzzer
mkdir -p /log/python_tests_log

cd /tezedge
git pull --rebase
rm -f ./target/fuzz/deps/*.gcda
cargo build -Z unstable-options --profile=fuzz

cp -f /tezedge/tezos/python-tests/daemons/* /tezos/tests_python/daemons/
cp -f /tezedge/tezos/python-tests/launchers/sandbox.py /tezos/tests_python/launchers/
cp -f /tezedge/tezos/python-tests/tools/constants.py /tezos/tests_python/tools/
cp -f /tezedge/light_node/etc/tezedge_sandbox/sandbox-patch-context.json /tezos/sandbox-patch-context.json
cp -f /tezedge/target/fuzz/light-node /tezos/
cp -f /tezedge/target/fuzz/protocol-runner /tezos/
cp /tezedge/tezos/sys/lib_tezos/artifacts/sapling-spend.params /tezos/
cp /tezedge/tezos/sys/lib_tezos/artifacts/sapling-output.params /tezos/
