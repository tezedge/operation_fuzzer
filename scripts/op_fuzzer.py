# Copyright(c) SimpleStaking, Viable Systems and Tezedge Contributors
# SPDX-License-Identifier: MIT

import os
import time
import signal
from typing import Counter
import psutil
import random as r
import construct as c
import subprocess
import report_ocaml
import pytest
import base58check
import ed25519
import pyblake2
from tools import utils, paths, constants

COVERAGE = True
ASYNC = 'true'
SENDER_SK = constants.IDENTITIES['bootstrap1']['secret'][len('unencrypted:'):]
CONTRACT_ID = constants.IDENTITIES['bootstrap1']['identity']
SOURCE = base58check.b58decode(CONTRACT_ID.encode())[3:-4]
BRANCH = None
LEVEL = 0
COUNTER = 0
CHAIN_ID = 'main'
BLOCK_ID = 'head'
BAKE = False


def timeout_handler(signum, frame):
    global BAKE
    BAKE = True
    # raise TimeoutError


def sign(data: bytes) -> bytes:
    hash = pyblake2.blake2b(b'\x03' + data, digest_size=32)
    sig_key = ed25519.SigningKey(base58check.b58decode(SENDER_SK)[4:-4])
    return sig_key.sign(hash.digest())


def rand_elems(subc, min_count=1, max_count=128):
    return lambda _: [None] * r.randint(min_count, max_count)


def relems_greedy(elem, min_count=1, max_count=128):
    return c.Default(c.GreedyRange(elem), rand_elems(elem, min_count, max_count))


def rand_operation_tag():
    return lambda _: r.choice(
        [
            1, 2, 3, 4, 5, 6, 7, 17, 20, 21,
            107, 108, 109, 110, 111, 112
        ])


def rand_entrypoint():
    return lambda _: r.choice([0, 1, 2, 3, 4, 255])


def rand_contract_id():
    return lambda _: r.choice([0, 1])


def rand_bool():
    return lambda _: r.choice([0, 255])


def rwrap(subc):
    return c.Default(subc, None)


def ruint(bits, min=None, max=None):
    subc = {
        8:  c.Int8ub,
        16:  c.Int16ub,
        32:  c.Int32ub,
        64:  c.Int64ub,
    }

    if min is None:
        min = 0

    if max is None:
        max = (1 << bits) - 1

    return c.Default(subc[bits], lambda _: r.randint(min, max))


def rsint(bits, min=None, max=None):
    subc = {
        8: c.Int8sb,
        16: c.Int16sb,
        32: c.Int32sb,
        64: c.Int64sb
    }

    if min is None:
        min = -(1 << (bits - 1))

    if max is None:
        max = (1 << (bits - 1)) - 1

    return c.Default(subc[bits], lambda _: r.randint(min, max))


def rbytes(byte_count, prefix=b''):
    return c.Default(c.Bytes(byte_count), lambda _: prefix + r.randbytes(byte_count - len(prefix)))


def rbranch():
    def branch(_):
        if BRANCH is None:
            return r.randbytes(32)
        else:
            return BRANCH

    return c.Default(c.Bytes(32), branch)


def rbytes_greedy(min=1, max=128):
    return c.Default(
        c.GreedyBytes,
        lambda _: r.randbytes(r.randint(min, max))
    )


def rbool():
    return c.Default(c.Int8ub, rand_bool())


# 012-Psithaca.inlined.endorsement_mempool.contents (43 bytes, 8-bit tag)
endorsement_mempool_contents = c.Struct(
    'tag' / c.Const(21, c.Int8ub),
    'slot' / ruint(16),
    'level' / c.Default(c.Int32sl, lambda _: LEVEL),
    'round' / rsint(32, min=0),
    'block_payload_hash' / rbytes(32, prefix=b'\001\106\242')
)

# 012-Psithaca.inlined.endorsement
inlined_endorsement = c.Struct(
    'branch' / rbranch(),
    'operations' / endorsement_mempool_contents,
    # rbytes_greedy(min=64, max=64)
    'signature' / rbytes(64, prefix=b'\004\130\043')
)

# Seed_nonce_revelation (tag 1)
Seed_nonce_revelation = c.Struct(
    'level' / c.Default(c.Int32sl, lambda _: LEVEL),
    'nonce' / rbytes(32)
)

# Double_endorsement_evidence (tag 2)
Double_endorsement_evidence = c.Struct(
    'op1' / c.Prefixed(c.Int32ub, inlined_endorsement),
    'op2' / c.Prefixed(c.Int32ub, inlined_endorsement),
)

# fitness.elem
fitness_elem = c.Struct(
    'version' / c.Prefixed(c.Int32ub, c.Const(2, c.Int8ub)),
    'level' / c.Prefixed(c.Int32ub, c.Default(c.Int32sl, lambda _: LEVEL)),
    'locked_round' / c.Prefixed(c.Int32ub, rsint(32)),
    'neg_predecessor_round' / c.Prefixed(c.Int32ub, rsint(32)),
    'round' / c.Prefixed(c.Int32ub, rsint(32))
)

# 012-Psithaca.block_header.alpha.full_header
full_header = c.Struct(
    'level' / c.Default(c.Int32sl, lambda _: LEVEL),
    'proto' / ruint(8),
    'predecessor' / rbytes(32, prefix=b'\001\052'),
    'timestamp' / rsint(64),  # TODO min,max
    'validation_pass' / ruint(8),
    'operations_hash' / rbytes(32, prefix=b'\029\159\109'),
    'fitness' / c.Prefixed(c.Int32ub, fitness_elem),
    'context' / rbytes(32, prefix=b'\079\199'),
    'payload_hash' / rbytes(32, prefix=b'\234\249'),
    'payload_round' / rsint(32, min=0),
    'proof_of_work_nonce' / rbytes(8),
    'has_seed_nonce_hash' / c.Const(255, c.Int8ub),  # rbool(),
    'seed_nonce_hash' / rbytes(32, prefix=b'\013\015\058\007'),
    'liquidity_baking_escape_vote' / c.Const(255, c.Int8ub),  # rbool(),
    'signature' / rbytes(64, prefix=b'\004\130\043')
)

# Double_baking_evidence (tag 3)
Double_baking_evidence = c.Struct(
    'bh1' / c.Prefixed(c.Int32ub, rwrap(full_header)),
    'bh2' / c.Prefixed(c.Int32ub, rwrap(full_header)),
)

# Activate_account (tag 4)
Activate_account = c.Struct(
    'pkh' / rbytes(20),
    'secret' / rbytes(20)
)


# public_key_hash (21 bytes, 8-bit tag)
public_key_hash = c.Struct(
    'tag' / c.Const(0, c.Int8ub),
    'operation' / c.Default(c.Bytes(20), SOURCE)
)

# Proposals (tag 5)
Proposals = c.Struct(
    'source' / public_key_hash,
    'period' / rsint(32),
    'proposals' / c.Prefixed(c.Int32ub, relems_greedy(rbytes(32)))
)

# Ballot (tag 6)
Ballot = c.Struct(
    'source' / public_key_hash,
    'period' / rsint(32),
    'proposal' / rbytes(32),
    'ballot' / rsint(8, min=0, max=2)
)

# 012-Psithaca.inlined.preendorsement.contents (43 bytes, 8-bit tag)
preendorsement_contents = c.Struct(
    'tag' / c.Const(20, c.Int8ub),
    'slot' / ruint(16),
    'level' / c.Default(c.Int32sl, lambda _: LEVEL),
    'round' / rsint(32, min=0),
    'block_payload_hash' / rbytes(32)
)

# 012-Psithaca.inlined.preendorsement
inlined_preendorsement = c.Struct(
    'branch' / rbranch(),
    'operations' / preendorsement_contents,
    'signature' / rbytes(64, prefix=b'\004\130\043')  # rbytes_greedy()
)

# Double_preendorsement_evidence (tag 7)
Double_preendorsement_evidence = c.Struct(
    'op1' / c.Prefixed(c.Int32ub, inlined_preendorsement),
    'op2' / c.Prefixed(c.Int32ub, inlined_preendorsement),
)

# Failing_noop (tag 17)
Failing_noop = c.Prefixed(c.Int32ub, rbytes_greedy())

# Preendorsement (tag 20)
Preendorsement = c.Struct(
    'slot' / ruint(16),
    'level' / c.Default(c.Int32sl, lambda _: LEVEL),
    'round' / rsint(32, min=0),
    'block_payload_hash' / rbytes(32)
)

# Endorsement (tag 21)
Endorsement = Preendorsement  # same layout

# N.t
N_t = c.Struct(
    'value' / ruint(8),
    'next_byte' / c.If(c.this.value > 127, rwrap(c.LazyBound(lambda: N_t))),
)

# public_key (Determined from data, 8-bit tag)
public_key = c.Struct(
    'tag' / c.Default(c.Int8ub, c.this._.source.tag),
    'operation' / c.Switch(c.this.tag, {
        0: rbytes(32),  # Ed25519
        1: rbytes(32),  # Secp256k1
        2: rbytes(32),  # P256
    })
)


# Reveal (tag 107)
Reveal = c.Struct(
    'source' / public_key_hash,
    'fee' / N_t,
    'counter' / c.Default(c.Int8ub, lambda _: COUNTER + 1),
    'gas_limit' / N_t,
    'storage_limit' / N_t,
    'public_key' / public_key
)


# 012-Psithaca.contract_id (22 bytes, 8-bit tag)
contract_id = c.Struct(
    'tag' / c.Default(c.Int8ub, rand_contract_id()),
    'operation' / c.Switch(
        c.this.tag,
        {
            0: public_key_hash,  # Implicit
            1: rbytes(21),  # Originated
        }
    )
)

# 012-Psithaca.entrypoint (Determined from data, 8-bit tag)
entrypoint = c.Struct(
    'tag' / c.Default(c.Int8ub, rand_entrypoint()),
    'field0' / c.If(c.this.tag == 255,
                    c.Prefixed(c.Int8ub, rbytes_greedy(max=31)))
)

# string_enum, int size based on enum len
michelson_v1_primitive = ruint(8, max=165)

prim_0_args_no_annots = c.Struct(
    'prim' / michelson_v1_primitive,
)

prim_0_args_some_annots = c.Struct(
    'prim' / michelson_v1_primitive,
    'annots' / c.Prefixed(c.Int32ub, rbytes_greedy(min=1, max=255))
)

prim_1_arg_no_annots = c.Struct(
    'prim' / michelson_v1_primitive,
    'arg' / rwrap(c.LazyBound(lambda: micheline_expr))
)

prim_1_args_some_annots = c.Struct(
    'prim' / michelson_v1_primitive,
    'arg' / rwrap(c.LazyBound(lambda: micheline_expr)),
    'annots' / c.Prefixed(c.Int32ub, rbytes_greedy(min=1, max=255))
)

prim_2_arg_no_annots = c.Struct(
    'prim' / michelson_v1_primitive,
    'arg1' / rwrap(c.LazyBound(lambda: micheline_expr)),
    'arg2' / rwrap(c.LazyBound(lambda: micheline_expr))
)

prim_2_arg_some_annots = c.Struct(
    'prim' / michelson_v1_primitive,
    'arg1' / rwrap(c.LazyBound(lambda: micheline_expr)),
    'arg2' / rwrap(c.LazyBound(lambda: micheline_expr)),
    'annots' / c.Prefixed(c.Int32ub, rbytes_greedy(min=1, max=255))
)

code = c.Struct(
    'tag' / c.Const(1, c.Int8ub),
    'bytes' / c.Prefixed(c.Int32ub, rbytes_greedy())
)


micheline_expr = c.Struct(
    'tag' / c.Default(c.Int8ub, lambda _: r.choice([0, 1, 2, 9])),
    'expr' / c.Switch(
        c.this.tag,
        {
            0: N_t,  # int_encoding
            1: c.Prefixed(c.Int32ub, rbytes_greedy()),  # string_encoding
            # seq_encoding = list(expr_encoding)
            2: c.Prefixed(c.Int32ub, relems_greedy(rwrap(c.LazyBound(lambda: micheline_expr)), max_count=2)),
            # 3: prim_0_args_no_annots,
            # 4: prim_0_args_some_annots,
            # 5: prim_1_arg_no_annots,
            # 6: prim_1_args_some_annots,
            # 7: prim_2_arg_no_annots,
            # 8: prim_2_arg_some_annots,
            # 9: rwrap(c.LazyBound(lambda: micheline_expr)),  # expr_encoding
            # 10: rbytes_greedy(min=1, max=255)  # bytes_encoding (TODO: size?)
        }
    )
)

params = c.Struct(
    'tag' / ruint(8, min=3, max=8),
    'expr' / c.Switch(
        c.this.tag,
        {
            3: prim_0_args_no_annots,
            4: prim_0_args_some_annots,
            5: prim_1_arg_no_annots,
            6: prim_1_args_some_annots,
            7: prim_2_arg_no_annots,
            8: prim_2_arg_some_annots,
        }
    )
)

# X_0
X_0 = c.Struct(
    'entrypoint' / entrypoint,
    'value' / c.Prefixed(c.Int32ub, params)
)


# Transaction (tag 108)
Transaction = c.Struct(
    'source' / public_key_hash,
    'fee' / N_t,
    'counter' / c.Default(c.Int8ub, lambda _: COUNTER + 1),
    'gas_limit' / N_t,
    'storage_limit' / N_t,
    'amount' / N_t,
    'destination' / contract_id,
    'has_parameters' / rbool(),
    'parameters' / c.If(c.this.has_parameters != 0, X_0)
)

# 012-Psithaca.scripted.contracts
scripted_contracts = c.Struct(
    'code' / c.Prefixed(c.Int32ub, code),
    'storage' / c.Prefixed(c.Int32ub, code)
)

# Origination (tag 109)
Origination = c.Struct(
    'source' / public_key_hash,
    'fee' / N_t,
    'counter' / c.Default(c.Int8ub, lambda _: COUNTER + 1),
    'gas_limit' / N_t,
    'storage_limit' / N_t,
    'balance' / N_t,
    'has_delegate' / c.Const(255, c.Int8ub),  # rbool(),
    'delegate' / c.If(c.this.has_delegate != 0, public_key_hash),
    'script' / scripted_contracts
)

# Delegation (tag 110)
Delegation = c.Struct(
    'source' / public_key_hash,
    'fee' / N_t,
    'counter' / c.Default(c.Int8ub, lambda _: COUNTER + 1),
    'gas_limit' / N_t,
    'storage_limit' / N_t,
    'has_delegate' / rbool(),
    'delegate' / c.If(c.this.has_delegate != 0, public_key_hash),
)

# Register_global_constant (tag 111)
Register_global_constant = c.Struct(
    'source' / public_key_hash,
    'fee' / N_t,
    'counter' / c.Default(c.Int8ub, lambda _: COUNTER + 1),
    'gas_limit' / N_t,
    'storage_limit' / N_t,
    'value' / c.Prefixed(c.Int32ub, micheline_expr)
)

# Set_deposits_limit (tag 112)
Set_deposits_limit = c.Struct(
    'source' / public_key_hash,
    'fee' / N_t,
    'counter' / c.Default(c.Int8ub, lambda _: COUNTER + 1),
    'gas_limit' / N_t,
    'storage_limit' / N_t,
    'has_limit' / rbool(),
    'limit' / c.If(c.this.has_limit != 0, N_t),
)


# 012-Psithaca.operation.alpha.contents (Determined from data, 8-bit tag)
Ithaca_operation_contents = c.Struct(
    'tag' / c.Default(c.Int8ub, rand_operation_tag()),
    'operation' / c.Switch(
        c.this.tag,
        {
            1: rwrap(Seed_nonce_revelation),
            2: rwrap(Double_endorsement_evidence),
            3: rwrap(Double_baking_evidence),
            4: rwrap(Activate_account),
            5: rwrap(Proposals),
            6: rwrap(Ballot),
            7: rwrap(Double_preendorsement_evidence),
            17: rwrap(Failing_noop),
            20: rwrap(Preendorsement),
            21: rwrap(Endorsement),
            107: rwrap(Reveal),
            108: rwrap(Transaction),
            109: rwrap(Origination),
            110: rwrap(Delegation),
            111: rwrap(Register_global_constant),
            112: rwrap(Set_deposits_limit)
        }
    )
)


"""
WARNING: *contents* is defined as a sequence of *Ithaca_operation_contents*,
but there is no size prefix. Without knowing the size of an operation there
doesn't seem to be a sound way of parsing it. Usually that size is obtained
from the upper transport layer. ATM this code will be used just for encoding
so this issue can be ignored.
"""
Ithaca_operation = c.Struct(
    'operation' / c.RawCopy(
        c.Struct(
            'branch' / rbranch(),
            'contents' / relems_greedy(Ithaca_operation_contents, max_count=2)
        )),
    'signature' / c.Checksum(c.Bytes(64), sign, c.this.operation.data)
)


def dump_coverage():
    threads = next(proc.threads() for proc in psutil.process_iter()
                   if 'protocol-runner' == proc.name())

    for tid in [t.id for t in threads]:
        if 'main' == psutil.Process(tid).name():
            print(f'Sending signal to OCaml\'s runtime ({tid})...')
            os.kill(tid, signal.SIGUSR2)
            time.sleep(1)
            return report_ocaml.generate_report()

    raise


@pytest.fixture(scope="class")
def client(sandbox):
    sandbox.add_node(0, params=constants.NODE_PARAMS)
    sandbox.add_node(1, params=constants.NODE_PARAMS)
    sandbox.add_node(2, params=constants.NODE_PARAMS)
    sandbox.add_node(3, params=constants.NODE_PARAMS)
    sandbox.add_baker(
        0,
        ['bootstrap2'],
        proto=constants.ITHACA_DAEMON,
    )
    sandbox.add_baker(
        1,
        ['bootstrap3'],
        proto=constants.ITHACA_DAEMON,
    )
    sandbox.add_baker(
        2,
        ['bootstrap4'],
        proto=constants.ITHACA_DAEMON,
    )
    sandbox.add_baker(
        3,
        ['bootstrap5'],
        proto=constants.ITHACA_DAEMON,
    )
    time.sleep(20)
    client = sandbox.client(0)
    parameters = constants.ITHACA_PARAMETERS
    client.activate_protocol_json(constants.ITHACA, parameters)
    yield client


@pytest.mark.incremental
class TestFuzz:
    def test_fuzz(self, client):
        signal.signal(signal.SIGALRM, timeout_handler)
        branch_b58 = client.rpc('get', 'chains/main/blocks/head/hash')
        global BRANCH
        global COUNTER
        global LEVEL
        BRANCH = base58check.b58decode(branch_b58.encode())[2:-4]
        LEVEL = 0
        iterations = 1
        cov_per = None
        covered_all = None
        total_all = None

        while True:
            signed_op = Ithaca_operation.build(None)

            try:
                block = client.rpc(
                    'get',
                    f'/chains/{CHAIN_ID}/blocks/{BLOCK_ID}'
                )
                LEVEL = int(block['header']['level'])
                counter = client.rpc(
                    'get',
                    f'/chains/{CHAIN_ID}/blocks/{BLOCK_ID}/'
                    f'context/contracts/{CONTRACT_ID}/counter',
                )
                COUNTER = int(counter)

                op_hash = client.rpc(
                    'post', f'/injection/operation?async={ASYNC}', signed_op.hex())
                # print(op_hash)

                if cov_per is not None:
                    print(
                        f'[COV] {cov_per:.1f}% {covered_all}/{total_all}')

            except subprocess.CalledProcessError:
                pass

            iterations += 1

            if COVERAGE and (iterations % 100) == 0:
                (cov_per, covered_all, total_all) = dump_coverage()
                subprocess.run(
                    'rm -f /tezos/tests_python/bisect*.coverage', shell=True)
