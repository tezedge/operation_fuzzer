# Quick instructions

This repository contains the script files needed to deploy and run *TezEdge's* operations fuzzer in the fuzzing CI.

1. Run `./deploy.sh`. This script will build the *fuzz_op* Docker container.
2. Run `./run.sh`. The scrip will run the *fuzz_op* container which will listen form *XMLRPC* requests at address `127.0.0.1:9002`.
3. The fuzzer can be restarted at any time by sending an *XMLRPC* request, this can be done by running the script at `scripts/restart_fuzzer.py`. In this restart process new code will be pulled and built from *TezEdge's* `develop` branch, this way the fuzzer can be integrated in CI.

# Operations fuzzer

This fuzzer is implemented as a Python script that makes use of the [Tezos' Python Execution and Testing Environment](https://tezos.gitlab.io/developer/python_testing_framework.html) and allows to craft and inject random (protocol-13, *Jakarta*) operations.

The fuzzer runs four nodes and four bakers in [sandboxed mode](https://tezos.gitlab.io/developer/python_testing_framework.html#a-simple-sandbox-scenario), this is the minum required to bake new blocks and do progress. Bootstrap accounts `bootstrap2-5` are used by bakers, and `bootstrap1` is used as source for the randomly generated operations, before injecting any operations protocol *Jakarta* is activated.

On every iteration the fuzzer will:
- Request via RPC the current block's *level*.
- Request via RPC the current contract's *counter*.
- Generate a random operation, sign it, and inject it via the `injection/operation` RPC.
- Every 100 iterations coverage counters are dumped and coverage reports are generated. Reports are stored in `/var/lib/fuzzing-data/reports/develop/.fuzzing.latest/operation_fuzzer/` in the host.

