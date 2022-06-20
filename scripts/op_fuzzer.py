# Copyright(c) SimpleStaking, Viable Systems and Tezedge Contributors
# SPDX-License-Identifier: MIT

import string
import os
import time
import signal
from typing import Counter, Sequence
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
CONTRACTS = None


def sign(data: bytes) -> bytes:
    hash = pyblake2.blake2b(b'\x03' + data, digest_size=32)
    sig_key = ed25519.SigningKey(base58check.b58decode(SENDER_SK)[4:-4])
    return sig_key.sign(hash.digest())


def rand_elems(subc, min_count=1, max_count=10):
    return lambda _: [None] * r.randint(min_count, max_count)


def relems_greedy(elem, min_count=1, max_count=10):
    return c.Default(c.GreedyRange(elem), rand_elems(elem, min_count, max_count))


def weighted_choice(choices):
    return r.choices(*list(zip(*choices)))[0]


def rand_operation_tag():
    return lambda _: weighted_choice([
        (1, 0.1),
        (2, 0.1),
        (3, 0.1),
        (4, 0.1),
        (5, 0.1),
        (6, 0.1),
        (7, 0.1),
        (17, 0.1),
        (20, 0.1),
        (21, 0.1),
        (107, 0.1),
        (108, 0.9),
        (109, 0.9),
        (110, 0.1),
        (111, 0.1),
        (112, 0.1),
        (150, 0.1),
        (152, 0.1),
        (152, 0.1),
        (153, 0.1),
        (154, 0.1),
        (155, 0.1),
        (157, 0.1),
        (158, 0.1),
        (200, 0.1),
        (201, 0.1),
        (202, 0.1),
        (203, 0.1)
    ])


def rand_contract_id():
    return lambda _: r.choice([0, 1])


def rand_bool():
    return lambda _: weighted_choice([(0, 0.1), (255, 0.9)])


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


def rbytes_greedy(min=1, max=20):
    return c.Default(
        c.GreedyBytes,
        lambda _: r.randbytes(r.randint(min, max))
    )


def rbool():
    return c.Default(c.Int8ub, rand_bool())


endorsement_mempool_contents = c.Struct(
    'tag' / c.Const(21, c.Int8ub),
    'slot' / ruint(16),
    'level' / c.Default(c.Int32sl, lambda _: LEVEL),
    'round' / rsint(32, min=0),
    'block_payload_hash' / rbytes(32, prefix=b'\001\106\242')
)

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

preendorsement_contents = c.Struct(
    'tag' / c.Const(20, c.Int8ub),
    'slot' / ruint(16),
    'level' / c.Default(c.Int32sl, lambda _: LEVEL),
    'round' / rsint(32, min=0),
    'block_payload_hash' / rbytes(32)
)

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


def rchars_greedy(min=1, max=10):
    return c.Default(
        c.GreedyBytes,
        lambda _: b''.join(r.choice(string.printable).encode()
                           for _ in range(r.randint(min, max)))
    )


def rannot_greedy(min=1, max=10, prefix='@:%'):
    chars = string.ascii_letters + string.digits + '@%_.'
    return c.Default(
        c.GreedyBytes,
        lambda _: r.choice(prefix).encode() + b''.join(r.choice(chars).encode()
                                                       for _ in range(r.randint(min, max-1)))
    )


string_expr = c.Prefixed(c.Int32ub, rchars_greedy())
annot_expr = c.Prefixed(c.Int32ub, rannot_greedy())


entrypoint_types = [0, 1, 2, 3, 4]  # , 255]

entrypoint = c.Struct(
    'tag' / c.Default(c.Int8ub, lambda _: r.choice(entrypoint_types)),
    'field0' / c.If(c.this.tag == 255,
                    c.Prefixed(c.Int8ub, rannot_greedy(prefix='%')))
)

# string_enum, int size based on enum len
michelson_v1_primitive = ruint(8, max=165)

prim_0_args_no_annots = c.Struct(
    'prim' / michelson_v1_primitive,
)

prim_0_args_some_annots = c.Struct(
    'prim' / michelson_v1_primitive,
    'annots' / annot_expr
)

prim_1_arg_no_annots = c.Struct(
    'prim' / michelson_v1_primitive,
    'arg' / rwrap(c.LazyBound(lambda: micheline_expr_no_seq))
)

prim_1_args_some_annots = c.Struct(
    'prim' / michelson_v1_primitive,
    'arg' / rwrap(c.LazyBound(lambda: micheline_expr_no_seq)),
    'annots' / annot_expr
)

prim_2_arg_no_annots = c.Struct(
    'prim' / michelson_v1_primitive,
    'arg1' / rwrap(c.LazyBound(lambda: micheline_expr_no_seq)),
    'arg2' / rwrap(c.LazyBound(lambda: micheline_expr_no_seq))
)

prim_2_arg_some_annots = c.Struct(
    'prim' / michelson_v1_primitive,
    'arg1' / rwrap(c.LazyBound(lambda: micheline_expr_no_seq)),
    'arg2' / rwrap(c.LazyBound(lambda: micheline_expr_no_seq)),
    'annots' / annot_expr
)

node = c.Switch(
    c.this.tag,
    {
        # integer
        0: N_t,
        # string
        1: c.Prefixed(c.Int32ub, rchars_greedy()),
        # sequence
        2: c.Prefixed(c.Int32ub, relems_greedy(rwrap(c.LazyBound(lambda: micheline_expr_no_seq)))),
        # primitive application
        3: prim_0_args_no_annots,
        4: prim_0_args_some_annots,
        5: prim_1_arg_no_annots,
        6: prim_1_args_some_annots,
        7: prim_2_arg_no_annots,
        8: prim_2_arg_some_annots,
        # bytes
        10: c.Prefixed(c.Int32ub, rbytes_greedy(min=1, max=10))
    }
)

# version to prevent excessive recursion
micheline_expr_no_seq = c.Struct(
    'tag' / c.Default(c.Int8ub,
                      lambda _: weighted_choice([
                          (0, 0.5),
                          (1, 0.5),
                          (2, 0.1),
                          (3, 0.9),
                          (4, 0.9),
                          # (5, 0.1),
                          # (6, 0.5),
                          # (7, 0.5),
                          # (8, 0.5),
                          (10, 0.5),
                      ])),
    'node' / node
)

micheline_expr = c.Struct(
    'tag' / c.Default(c.Int8ub,
                      lambda _: weighted_choice([
                          (0, 0.1),
                          (1, 0.1),
                          (2, 0.9),
                          (3, 0.1),
                          (4, 0.1),
                          (5, 0.1),
                          (6, 0.1),
                          (7, 0.1),
                          (8, 0.1),
                          (10, 0.1),
                      ])),
    'node' / node
)

# X_0
X_0 = c.Struct(
    'entrypoint' / entrypoint,
    'value' / c.Prefixed(c.Int32ub, micheline_expr)
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

scripted_contracts = c.Struct(
    'code' / c.Prefixed(c.Int32ub, micheline_expr),
    'storage' / c.Prefixed(c.Int32ub, micheline_expr)
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


# Tx_rollup_origination (tag 150)
Tx_rollup_origination = c.Struct(
    'source' / public_key_hash,
    'fee' / N_t,
    'counter' / c.Default(c.Int8ub, lambda _: COUNTER + 1),
    'gas_limit' / N_t,
    'storage_limit' / N_t,
)


# Tx_rollup_submit_batch (tag 151)
Tx_rollup_submit_batch = c.Struct(
    'source' / public_key_hash,
    'fee' / N_t,
    'counter' / c.Default(c.Int8ub, lambda _: COUNTER + 1),
    'gas_limit' / N_t,
    'storage_limit' / N_t,
    'rollup' / rbytes(20),
    'content' / c.Prefixed(c.Int32ub, rbytes_greedy(min=4, max=64)),
    'has_burn_limit' / rbool(),
    'burn_limit' / c.If(c.this.has_burn_limit != 0, N_t)
)

X_135 = c.Struct(
    'tag' / c.Default(c.Int8ub,
                      lambda _: weighted_choice([(0, 0.5), (1, 0.5)])),
    'Commitment_hash' / c.If(c.this.tag == 1, rbytes(32))
)

X_134 = c.Struct(
    'level' / c.Default(c.Int32sl, lambda _: LEVEL),
    'messages' / c.Prefixed(c.Int32ub, rbytes_greedy(min=4, max=64)),
    'predecessor' / X_135,
    'inbox_merkle_root' / rbytes(32)
)

# Tx_rollup_commit (tag 152)
Tx_rollup_commit = c.Struct(
    'source' / public_key_hash,
    'fee' / N_t,
    'counter' / c.Default(c.Int8ub, lambda _: COUNTER + 1),
    'gas_limit' / N_t,
    'storage_limit' / N_t,
    'rollup' / rbytes(20),
    'commitment' / c.Prefixed(c.Int32ub, X_134),
)


# Tx_rollup_return_bond (tag 153)
Tx_rollup_return_bond = c.Struct(
    'source' / public_key_hash,
    'fee' / N_t,
    'counter' / c.Default(c.Int8ub, lambda _: COUNTER + 1),
    'gas_limit' / N_t,
    'storage_limit' / N_t,
    'rollup' / rbytes(20),
)

# Tx_rollup_finalize_commitment (tag 154)
Tx_rollup_finalize_commitment = c.Struct(
    'source' / public_key_hash,
    'fee' / N_t,
    'counter' / c.Default(c.Int8ub, lambda _: COUNTER + 1),
    'gas_limit' / N_t,
    'storage_limit' / N_t,
    'rollup' / rbytes(20),
)


# Tx_rollup_remove_commitment (tag 155)
Tx_rollup_remove_commitment = c.Struct(
    'source' / public_key_hash,
    'fee' / N_t,
    'counter' / c.Default(c.Int8ub, lambda _: COUNTER + 1),
    'gas_limit' / N_t,
    'storage_limit' / N_t,
    'rollup' / rbytes(20),
)

X_6 = c.Struct(
    'tag' / c.Default(c.Int8ub,
                      lambda _: weighted_choice([
                          (0, 0.5),
                          (1, 0.5),
                          (2, 0.5),
                          (3, 0.5)
                      ])),
    'type' / c.Switch(
        c.this.tag,
        {
            0: ruint(8),
            1: ruint(16),
            2: ruint(32),
            3: ruint(64)
        }
    )
)

X_5 = c.Struct(
    'sender' / rbytes(21),
    'destination' / rbytes(20),
    'ticket_hash' / rbytes(32),
    'amount' / X_6
)

X_7 = c.Struct(
    'tag' / c.Default(c.Int8ub,
                      lambda _: weighted_choice([(0, 0.5), (1, 0.5)])),
    'type' / c.Switch(
        c.this.tag,
        {
            # Batch
            0: c.Prefixed(c.Int32ub, rbytes_greedy(min=4, max=64)),
            # Deposit
            1: X_5,
        }
    )
)

X_127 = rbytes(32)

X_119 = c.Sequence(rbytes(32), rbytes(32))

X_114 = c.Prefixed(c.Int8ub, rbytes_greedy(min=4, max=64))

X_115 = c.Struct(
    'tag' / c.Default(c.Int8ub,
                      lambda _: weighted_choice([(0, 0.5), (1, 0.5)])),
    'context_hash' / rbytes(32)
)

X_14 = c.Sequence(X_114, X_115)

X_132 = c.Struct(
    'tag' / c.Default(c.Int8ub,
                      lambda _: weighted_choice([
                          (0, 0.5),
                          (1, 0.5),
                          (2, 0.5),
                          (3, 0.5),
                          (4, 0.5),
                          (5, 0.5),
                          (6, 0.5),
                          (7, 0.5),
                          (8, 0.5),
                          (9, 0.5),
                          (10, 0.5),
                          (11, 0.5),
                          (12, 0.5),
                          (13, 0.5),
                          (14, 0.5),
                          (15, 0.5),
                          (128, 0.5),
                          (129, 0.5),
                          (130, 0.5),
                          (131, 0.5),
                          (192, 0.5),
                          (193, 0.5),
                          (195, 0.5),
                          (224, 0.5),
                          (225, 0.5),
                          (226, 0.5),
                          (227, 0.5)
                      ])),
    'type' / c.Switch(
        c.this.tag,
        {
            0: ruint(8),
            1: ruint(16),
            2: rsint(32),
            3: rsint(64),
            4: c.Sequence(ruint(8), X_127),
            5: c.Sequence(ruint(16), X_127),
            6: c.Sequence(rsint(32), X_127),
            7: c.Sequence(rsint(64), X_127),
            8: c.Sequence(ruint(8), X_127),
            9: c.Sequence(ruint(16), X_127),
            10: c.Sequence(rsint(32), X_127),
            11: c.Sequence(rsint(64), X_127),
            12: c.Sequence(ruint(8), X_119),
            13: c.Sequence(ruint(16), X_119),
            14: c.Sequence(rsint(32), X_119),
            15: c.Sequence(rsint(64), X_119),
            129: X_14,
            130: c.Sequence(X_14, X_14),
            131: c.Prefixed(c.Int32ub, relems_greedy(X_14)),
            192: c.Prefixed(c.Int8ub, rbytes_greedy(min=4, max=64)),
            193: c.Prefixed(c.Int16ub, rbytes_greedy(min=4, max=64)),
            195: c.Prefixed(c.Int32ub, rbytes_greedy(min=4, max=64)),
            224: c.Sequence(rsint(8), X_114, rbytes(32)),
            225: c.Sequence(rsint(16), X_114, rbytes(32)),
            226: c.Sequence(rsint(32), X_114, rbytes(32)),
            227: c.Sequence(rsint(64), X_114, rbytes(32)),
        }
    )
)


X_9 = c.Prefixed(c.Int32ub, relems_greedy(X_132))

X_133 = c.Struct(
    'tag' / c.Default(c.Int8ub,
                      lambda _: weighted_choice([
                          (0, 0.5),
                          (1, 0.5),
                          (2, 0.5),
                          (3, 0.5)
                      ])),
    'data' / c.Sequence(rsint(16), rbytes(32), rbytes(32), X_9)
)

X_8 = c.Struct(
    'context_hash' / rbytes(32),
    'withdraw_list_hash' / rbytes(32),
)

# Tx_rollup_rejection (tag 156)
Tx_rollup_rejection = c.Struct(
    'source' / public_key_hash,
    'fee' / N_t,
    'counter' / c.Default(c.Int8ub, lambda _: COUNTER + 1),
    'gas_limit' / N_t,
    'storage_limit' / N_t,
    'rollup' / rbytes(20),
    'level' / c.Default(c.Int32sl, lambda _: LEVEL),
    'message' / X_7,
    'message_position' / N_t,
    'message_path' / c.Prefixed(c.Int32ub, rbytes_greedy(min=4, max=64)),
    'message_result_hash' / rbytes(32),
    'message_result_path' /
    c.Prefixed(c.Int32ub, rbytes_greedy(min=4, max=64)),
    'previous_message_result' / X_8,
    'previous_message_result_path' /
    c.Prefixed(c.Int32ub, rbytes_greedy(min=4, max=64)),
    'proof' / X_133
)

X_3 = c.Struct(
    'contents' / c.Prefixed(c.Int32ub, rbytes_greedy(min=4, max=64)),
    'ty' / c.Prefixed(c.Int32ub, rbytes_greedy(min=4, max=64)),
    'ticketer' / contract_id,
    'amount' / X_6,
    'claimer' / public_key_hash
)


Tx_rollup_dispatch_tickets = c.Struct(
    'source' / public_key_hash,
    'fee' / N_t,
    'counter' / c.Default(c.Int8ub, lambda _: COUNTER + 1),
    'gas_limit' / N_t,
    'storage_limit' / N_t,
    'rollup' / rbytes(20),
    'level' / c.Default(c.Int32sl, lambda _: LEVEL),
    'context_hash' / rbytes(32),
    'message_index' / rsint(32),
    'message_result_path' /
    c.Prefixed(c.Int32ub, rbytes_greedy(min=4, max=64)),
    'tickets_info' / c.Prefixed(c.Int32ub, relems_greedy(X_3)),
)

Transfer_ticket = c.Struct(
    'source' / public_key_hash,
    'fee' / N_t,
    'counter' / c.Default(c.Int8ub, lambda _: COUNTER + 1),
    'gas_limit' / N_t,
    'storage_limit' / N_t,
    'ticket_contents' /
    c.Prefixed(c.Int32ub, rbytes_greedy(min=4, max=64)),
    'ticket_ty' /
    c.Prefixed(c.Int32ub, rbytes_greedy(min=4, max=64)),
    'ticket_ticketer' / contract_id,
    'ticket_amount' / N_t,
    'destination' / contract_id,
    'entrypoint' /
    c.Prefixed(c.Int32ub, rbytes_greedy(min=4, max=64)),
)

X_2 = ruint(16)

Sc_rollup_originate = c.Struct(
    'source' / public_key_hash,
    'fee' / N_t,
    'counter' / c.Default(c.Int8ub, lambda _: COUNTER + 1),
    'gas_limit' / N_t,
    'storage_limit' / N_t,
    'kind' / X_2,
    'boot_sector' /
    c.Prefixed(c.Int32ub, rbytes_greedy(min=4, max=64)),
)

X_1 = c.Prefixed(c.Int32ub, rbytes_greedy(min=4, max=64))

Sc_rollup_add_messages = c.Struct(
    'source' / public_key_hash,
    'fee' / N_t,
    'counter' / c.Default(c.Int8ub, lambda _: COUNTER + 1),
    'gas_limit' / N_t,
    'storage_limit' / N_t,
    'rollup_address' /
    c.Prefixed(c.Int32ub, rbytes_greedy(min=4, max=64)),
    'message' / c.Prefixed(c.Int32ub, relems_greedy(X_1)),
)

Sc_rollup_cement = c.Struct(
    'source' / public_key_hash,
    'fee' / N_t,
    'counter' / c.Default(c.Int8ub, lambda _: COUNTER + 1),
    'gas_limit' / N_t,
    'storage_limit' / N_t,
    'rollup_address' /
    c.Prefixed(c.Int32ub, rbytes_greedy(min=4, max=64)),
    'commitment' / rbytes(32)
)

X_0_ = c.Struct(
    'compressed_state' / rbytes(32),
    'inbox_level' / rsint(32),
    'predecessor' / rbytes(32),
    'number_of_messages' / rsint(32),
    'number_of_ticks' / rsint(32),
)


Sc_rollup_publish = c.Struct(
    'source' / public_key_hash,
    'fee' / N_t,
    'counter' / c.Default(c.Int8ub, lambda _: COUNTER + 1),
    'gas_limit' / N_t,
    'storage_limit' / N_t,
    'rollup_address' /
    c.Prefixed(c.Int32ub, rbytes_greedy(min=4, max=64)),
    'commitment' / X_0_
)


operation_contents = c.Struct(
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
            112: rwrap(Set_deposits_limit),
            150: rwrap(Tx_rollup_origination),
            152: rwrap(Tx_rollup_submit_batch),
            152: rwrap(Tx_rollup_commit),
            153: rwrap(Tx_rollup_return_bond),
            154: rwrap(Tx_rollup_finalize_commitment),
            155: rwrap(Tx_rollup_remove_commitment),
            157: rwrap(Tx_rollup_dispatch_tickets),
            158: rwrap(Transfer_ticket),
            200: rwrap(Sc_rollup_originate),
            201: rwrap(Sc_rollup_add_messages),
            202: rwrap(Sc_rollup_cement),
            203: rwrap(Sc_rollup_publish),

        }
    )
)


operation = c.Struct(
    'operation' / c.RawCopy(
        c.Struct(
            'branch' / rbranch(),
            'contents' / relems_greedy(operation_contents, max_count=2)
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
            time.sleep(4)
            return report_ocaml.generate_report()

    raise


@ pytest.fixture(scope="class")
def client(sandbox):
    sandbox.add_node(0, params=constants.NODE_PARAMS)
    time.sleep(2)
    sandbox.add_node(1, params=constants.NODE_PARAMS)
    time.sleep(2)
    sandbox.add_node(2, params=constants.NODE_PARAMS)
    time.sleep(2)
    sandbox.add_node(3, params=constants.NODE_PARAMS)
    time.sleep(2)
    sandbox.add_baker(
        0,
        ['bootstrap2'],
        proto=constants.JAKARTA_DAEMON,
    )
    time.sleep(2)
    sandbox.add_baker(
        1,
        ['bootstrap3'],
        proto=constants.JAKARTA_DAEMON,
    )
    time.sleep(2)
    sandbox.add_baker(
        2,
        ['bootstrap4'],
        proto=constants.JAKARTA_DAEMON,
    )
    time.sleep(2)
    sandbox.add_baker(
        3,
        ['bootstrap5'],
        proto=constants.JAKARTA_DAEMON,
    )
    time.sleep(10)
    client = sandbox.client(0)
    parameters = constants.JAKARTA_PARAMETERS
    parameters['hard_gas_limit_per_operation'] = '104000000000'
    parameters['hard_gas_limit_per_block'] = '5200000000000'
    parameters['hard_storage_limit_per_operation'] = '600000000000'
    client.activate_protocol_json(constants.JAKARTA, parameters)
    yield client


@ pytest.mark.incremental
class TestFuzz:
    def test_fuzz(self, client):
        global BRANCH
        global COUNTER
        global LEVEL
        global CONTRACTS
        LEVEL = 0
        iterations = 1
        cov_per = None
        covered_all = None
        total_all = None
        time.sleep(10)

        while True:
            signed_op = operation.build(None)

            try:
                block = client.rpc(
                    'get',
                    f'/chains/{CHAIN_ID}/blocks/{BLOCK_ID}'
                )
                branch = block['hash']
                BRANCH = base58check.b58decode(branch.encode())[2:-4]
                LEVEL = int(block['header']['level'])
                counter = client.rpc(
                    'get',
                    f'/chains/{CHAIN_ID}/blocks/{BLOCK_ID}/'
                    f'context/contracts/{CONTRACT_ID}/counter',
                )
                COUNTER = int(counter)
                # CONTRACTS = client.rpc(
                #    'get',
                #    f'/chains/{CHAIN_ID}/blocks/{BLOCK_ID}/'
                #    f'context/contracts'
                # )

                op_hash = client.rpc(
                    'post', f'/injection/operation?async={ASYNC}', signed_op.hex(), params=['-l'])
                # print(op_hash)

                if cov_per is not None:
                    print(
                        f'[COV] {cov_per:.1f}% {covered_all}/{total_all}')

            except subprocess.CalledProcessError:
                raise

            iterations += 1

            if COVERAGE and (iterations % 100) == 0:
                (cov_per, covered_all, total_all) = dump_coverage()
                subprocess.run(
                    'rm -f /tezos/tests_python/bisect*.coverage', shell=True)
