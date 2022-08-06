#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import random

from eth import constants
from eth._utils.address import force_bytes_to_address
from eth_hash.auto import keccak
from eth_typing import Address, Hash32
from eth_utils import to_bytes, to_normalized_address, to_hex

from eth.chains.mainnet import MainnetHomesteadVM
from eth.constants import BLANK_ROOT_HASH, EMPTY_SHA3
from eth.db import BaseAtomicDB
from eth.db.account import BaseAccountDB
from eth.db.typing import JournalDBCheckpoint
from eth.rlp.accounts import Account
from eth.tools._utils.normalization import to_int
from eth.validation import validate_uint256, validate_canonical_address, validate_is_bytes

from eth.vm.forks import FrontierVM, TangerineWhistleVM, SpuriousDragonVM, ByzantiumVM, PetersburgVM
from eth.vm.forks.byzantium import ByzantiumState
from eth.vm.forks.byzantium.computation import ByzantiumComputation
from eth.vm.forks.frontier import FrontierState
from eth.vm.forks.frontier.computation import FrontierComputation
from eth.vm.forks.homestead import HomesteadState
from eth.vm.forks.homestead.computation import HomesteadComputation
from eth.vm.forks.petersburg import PetersburgState
from eth.vm.forks.petersburg.computation import PetersburgComputation
from eth.vm.forks.spurious_dragon import SpuriousDragonState
from eth.vm.forks.spurious_dragon.computation import SpuriousDragonComputation
from eth.vm.forks.tangerine_whistle import TangerineWhistleState
from eth.vm.forks.tangerine_whistle.computation import TangerineWhistleComputation

from web3 import HTTPProvider
from web3 import Web3

from utils import settings

global BLOCK_ID
BLOCK_ID = "latest"

# STORAGE EMULATOR
class EmulatorAccountDB(BaseAccountDB):
    def __init__(self, db: BaseAtomicDB, state_root: Hash32 = BLANK_ROOT_HASH) -> None:
        if settings.REMOTE_FUZZING and settings.RPC_HOST and settings.RPC_PORT:
            self._w3 = Web3(HTTPProvider('http://%s:%s' % (settings.RPC_HOST, settings.RPC_PORT)))
            self._remote = self._w3.eth
        else:
            self._remote = None
        self.state_root = BLANK_ROOT_HASH
        self._raw_store_db = db
        self.snapshot = None

    def set_snapshot(self, snapshot):
        self.snapshot = snapshot

    @property
    def state_root(self) -> Hash32:
        return self._state_root

    @state_root.setter
    def state_root(self, value: Hash32) -> None:
        self._state_root = value

    @property
    def _storage_emulator(self):
        return self._raw_store_db["storage"]

    @property
    def _account_emulator(self):
        return self._raw_store_db["account"]

    @property
    def _code_storage_emulator(self):
        return self._raw_store_db["code"]

    def get_storage(self, address: Address, slot: int, from_journal: bool = True) -> int:
        validate_canonical_address(address, title="Storage Address")
        validate_uint256(slot, title="Storage Slot")
        if address in self._storage_emulator and slot in self._storage_emulator[address] or not self._remote:
            try:
                return self._storage_emulator[address][slot]
            except KeyError:
                return 0
        else:
            result = self._remote.getStorageAt(address, slot, "latest")
            result = to_int(result.hex())
            self.set_storage(address, slot, result)
            if self.snapshot != None:
                if address not in self.snapshot["storage"]:
                    self.snapshot["storage"][address] = dict()
                self.snapshot["storage"][address][slot] = result
            return result

    def set_storage(self, address: Address, slot: int, value: int) -> None:
        validate_uint256(value, title="Storage Value")
        validate_uint256(slot, title="Storage Slot")
        validate_canonical_address(address, title="Storage Address")
        if address not in self._storage_emulator:
            self._storage_emulator[address] = dict()
        self._storage_emulator[address][slot] = value

    def delete_storage(self, address: Address) -> None:
        validate_canonical_address(address, title="Storage Address")
        if address in self._storage_emulator:
            del self._storage_emulator[address]

    def _get_account(self, address: Address) -> Account:
        if address in self._account_emulator:
            account = self._account_emulator[address]
        elif not self._remote:
            account = Account()
        else:
            code = self._remote.getCode(address, BLOCK_ID)
            if code:
                code_hash = keccak(code)
                self._code_storage_emulator[code_hash] = code
                if self.snapshot != None:
                    self.snapshot["code"][code_hash] = code
            else:
                code_hash = EMPTY_SHA3
            account = Account(
                int(self._remote.getTransactionCount(address, BLOCK_ID)) + 1,
                self._remote.getBalance(address, BLOCK_ID),
                BLANK_ROOT_HASH,
                code_hash
            )
            if self.snapshot != None:
                self.snapshot["account"][address] = account
            self._set_account(address, account)
        return account

    def _has_account(self, address: Address) -> bool:
        return address in self._account_emulator

    def _set_account(self, address: Address, account: Account) -> None:
        self._account_emulator[address] = account

    def get_nonce(self, address: Address) -> int:
        validate_canonical_address(address, title="Storage Address")
        a = self._get_account(address)
        return a.nonce

    def set_nonce(self, address: Address, nonce: int) -> None:
        validate_canonical_address(address, title="Storage Address")
        validate_uint256(nonce, title="Nonce")
        account = self._get_account(address)
        self._set_account(address, account.copy(nonce=nonce))

    def increment_nonce(self, address: Address):
        current_nonce = self.get_nonce(address)
        self.set_nonce(address, current_nonce + 1)

    def get_balance(self, address: Address) -> int:
        validate_canonical_address(address, title="Storage Address")
        return self._get_account(address).balance

    def set_balance(self, address: Address, balance: int) -> None:
        validate_canonical_address(address, title="Storage Address")
        validate_uint256(balance, title="Account Balance")
        account = self._get_account(address)
        self._set_account(address, account.copy(balance=balance))

    def set_code(self, address: Address, code: bytes) -> None:
        validate_canonical_address(address, title="Storage Address")
        validate_is_bytes(code, title="Code")
        account = self._get_account(address)
        code_hash = keccak(code)
        self._code_storage_emulator[code_hash] = code
        self._set_account(address, account.copy(code_hash=code_hash))

    def get_code(self, address: Address) -> bytes:
        validate_canonical_address(address, title="Storage Address")
        code_hash = self.get_code_hash(address)
        if code_hash == EMPTY_SHA3:
            return b''
        elif code_hash in self._code_storage_emulator:
            return self._code_storage_emulator[code_hash]

    def get_code_hash(self, address: Address) -> Hash32:
        validate_canonical_address(address, title="Storage Address")
        account = self._get_account(address)
        return account.code_hash

    def delete_code(self, address: Address) -> None:
        validate_canonical_address(address, title="Storage Address")
        account = self._get_account(address)
        code_hash = account.code_hash
        self._set_account(address, account.copy(code_hash=EMPTY_SHA3))
        if code_hash in self._code_storage_emulator:
            del self._code_storage_emulator[code_hash]

    def account_is_empty(self, address: Address) -> bool:
        return not self.account_has_code_or_nonce(address) and self.get_balance(address) == 0

    def account_has_code_or_nonce(self, address):
        return self.get_nonce(address) != 0 or self.get_code_hash(address) != EMPTY_SHA3

    def account_exists(self, address: Address) -> bool:
        validate_canonical_address(address, title="Storage Address")
        return address in self._account_emulator

    def touch_account(self, address: Address) -> None:
        validate_canonical_address(address, title="Storage Address")
        account = self._get_account(address)
        self._set_account(address, account)

    def delete_account(self, address: Address) -> None:
        validate_canonical_address(address, title="Storage Address")
        self.delete_code(address)
        if address in self._storage_emulator:
            del self._storage_emulator[address]
        if address in self._account_emulator:
            del self._account_emulator[address]

    def record(self) -> BaseAtomicDB:
        import copy
        checkpoint = copy.deepcopy(self._raw_store_db)
        return checkpoint

    def discard(self, checkpoint: BaseAtomicDB) -> None:
        import copy
        self._raw_store_db = copy.deepcopy(checkpoint)

    def commit(self, checkpoint: JournalDBCheckpoint) -> None:
        pass

    def make_state_root(self) -> Hash32:
        return None

    def persist(self) -> None:
        pass

    def has_root(self, state_root: bytes) -> bool:
        return False

def get_block_hash_for_testing(self, block_number):
    if block_number >= self.block_number:
        return b''
    elif block_number < self.block_number - 256:
        return b''
    else:
        return keccak(to_bytes(text="{0}".format(block_number)))

def fuzz_timestamp_opcode_fn(computation) -> None:
    if settings.ENVIRONMENTAL_INSTRUMENTATION and hasattr(computation.state, "fuzzed_timestamp") and computation.state.fuzzed_timestamp is not None:
        computation.stack_push_int(computation.state.fuzzed_timestamp)
    else:
        computation.stack_push_int(computation.state.timestamp)

def fuzz_blocknumber_opcode_fn(computation) -> None:
    if settings.ENVIRONMENTAL_INSTRUMENTATION and hasattr(computation.state, "fuzzed_blocknumber") and computation.state.fuzzed_blocknumber is not None:
        computation.stack_push_int(computation.state.fuzzed_blocknumber)
    else:
        computation.stack_push_int(computation.state.block_number)

def fuzz_call_opcode_fn(computation, opcode_fn) -> None:
    gas = computation.stack_pop1_int()
    to = computation.stack_pop1_bytes()
    _to = to_normalized_address(to_hex(force_bytes_to_address(to)))
    if settings.ENVIRONMENTAL_INSTRUMENTATION and hasattr(computation.state, "fuzzed_call_return") and computation.state.fuzzed_call_return is not None\
            and _to in computation.state.fuzzed_call_return and computation.state.fuzzed_call_return[_to] is not None:
        (
            value,
            memory_input_start_position,
            memory_input_size,
            memory_output_start_position,
            memory_output_size,
        ) = computation.stack_pop_ints(5)
        computation.memory_write(memory_output_start_position, memory_output_size, b'\x00' * memory_output_size if random.randint(1, 2) == 1 else b'\xff' * memory_output_size)
        computation.stack_push_int(computation.state.fuzzed_call_return[_to])
    else:
        computation.stack_push_bytes(to)
        computation.stack_push_int(gas)
        opcode_fn(computation=computation)
    return _to

def fuzz_staticcall_opcode_fn(computation, opcode_fn) -> None:
    gas = computation.stack_pop1_int()
    to = computation.stack_pop1_bytes()
    _to = to_normalized_address(to_hex(force_bytes_to_address(to)))
    if settings.ENVIRONMENTAL_INSTRUMENTATION and hasattr(computation.state, "fuzzed_call_return") and computation.state.fuzzed_call_return is not None\
            and _to in computation.state.fuzzed_call_return and computation.state.fuzzed_call_return[_to] is not None:
        (
            memory_input_start_position,
            memory_input_size,
            memory_output_start_position,
            memory_output_size,
        ) = computation.stack_pop_ints(4)
        computation.memory_write(memory_output_start_position, memory_output_size, b'\x00' * memory_output_size if random.randint(1, 2) == 1 else b'\xff' * memory_output_size)
        computation.stack_push_int(computation.state.fuzzed_call_return[_to])
    else:
        computation.stack_push_bytes(to)
        computation.stack_push_int(gas)
        opcode_fn(computation=computation)
    return _to

def fuzz_extcodesize_opcode_fn(computation, opcode_fn) -> None:
    to = computation.stack_pop1_bytes()
    _to = to_normalized_address(to_hex(force_bytes_to_address(to)))
    if settings.ENVIRONMENTAL_INSTRUMENTATION and hasattr(computation.state, "fuzzed_extcodesize") and computation.state.fuzzed_extcodesize is not None\
            and _to in computation.state.fuzzed_extcodesize and computation.state.fuzzed_extcodesize[_to] is not None:
        computation.stack_push_int(computation.state.fuzzed_extcodesize[_to])
    else:
        computation.stack_push_bytes(to)
        opcode_fn(computation=computation)

def fuzz_returndatasize_opcode_fn(previous_call_address, computation, opcode_fn) -> None:
    opcode_fn(computation=computation)
    size = computation.stack_pop1_int()
    if settings.ENVIRONMENTAL_INSTRUMENTATION and hasattr(computation.state, "fuzzed_returndatasize") and computation.state.fuzzed_returndatasize is not None\
            and previous_call_address in computation.state.fuzzed_returndatasize and computation.state.fuzzed_returndatasize[previous_call_address] is not None:
        computation.stack_push_int(computation.state.fuzzed_returndatasize[previous_call_address])
    else:
        computation.stack_push_int(size)

def fuzz_balance_opcode_fn(computation, opcode_fn) -> None:
    if settings.ENVIRONMENTAL_INSTRUMENTATION and hasattr(computation.state, "fuzzed_balance") and computation.state.fuzzed_balance is not None:
        computation.stack_pop1_bytes()
        computation.stack_push_int(computation.state.fuzzed_balance)
    else:
        opcode_fn(computation=computation)

def fuzz_apply_computation(cls, state, message, transaction_context):
    cls = cls.__class__
    with cls(state, message, transaction_context) as computation:

        # Early exit on pre-compiles
        from eth.vm.computation import NO_RESULT
        precompile = computation.precompiles.get(message.code_address, NO_RESULT)
        if precompile is not NO_RESULT:
            precompile(computation)
            return computation

        opcode_lookup = computation.opcodes
        computation.trace = list()
        previous_stack = []
        previous_call_address = None
        memory = None

        for opcode in computation.code:
            try:
                opcode_fn = opcode_lookup[opcode]
            except KeyError:
                from eth.vm.logic.invalid import InvalidOpcode
                opcode_fn = InvalidOpcode(opcode)

            from eth.exceptions import Halt
            from copy import deepcopy

            previous_pc = computation.code.pc
            previous_gas = computation.get_gas_remaining()

            try:
                if   opcode == 0x42:  # TIMESTAMP
                    fuzz_timestamp_opcode_fn(computation=computation)
                elif opcode == 0x43:  # NUMBER
                    fuzz_blocknumber_opcode_fn(computation=computation)
                elif opcode == 0x31:  # BALANCE
                    fuzz_balance_opcode_fn(computation=computation, opcode_fn=opcode_fn)
                elif opcode == 0xf1: # CALL
                    previous_call_address = fuzz_call_opcode_fn(computation=computation, opcode_fn=opcode_fn)
                elif opcode == 0xfa: # STATICCALL
                    previous_call_address = fuzz_staticcall_opcode_fn(computation=computation, opcode_fn=opcode_fn)
                elif opcode == 0x3b: # EXTCODESIZE
                    fuzz_extcodesize_opcode_fn(computation=computation, opcode_fn=opcode_fn)
                elif opcode == 0x3d: # RETURNDATASIZE
                    fuzz_returndatasize_opcode_fn(previous_call_address, computation=computation, opcode_fn=opcode_fn)
                elif opcode == 0x20: # SHA3
                    start_position, size = computation.stack_pop_ints(2)
                    memory = computation.memory_read_bytes(start_position, size)
                    computation.stack_push_int(size)
                    computation.stack_push_int(start_position)
                    opcode_fn(computation=computation)
                else:
                    opcode_fn(computation=computation)
            except Halt:
                break
            finally:
                computation.trace.append(
                    {
                        "pc": max(0, previous_pc - 1),
                        "op": opcode_fn.mnemonic,
                        "depth": computation.msg.depth + 1,
                        "error": deepcopy(computation._error),
                        "stack": previous_stack,
                        "memory": memory,
                        "gas": computation.get_gas_remaining(),
                        "gas_used_by_opcode" : previous_gas - computation.get_gas_remaining()
                    }
                )
                previous_stack = list(computation._stack.values)
    return computation

# VMs

# FRONTIER
FrontierComputationForFuzzTesting = FrontierComputation.configure(
    __name__='FrontierComputationForFuzzTesting',
    apply_computation=fuzz_apply_computation,
)
FrontierStateForFuzzTesting = FrontierState.configure(
    __name__='FrontierStateForFuzzTesting',
    get_ancestor_hash=get_block_hash_for_testing,
    computation_class=FrontierComputationForFuzzTesting,
    account_db_class=EmulatorAccountDB,
)
FrontierVMForFuzzTesting = FrontierVM.configure(
    __name__='FrontierVMForFuzzTesting',
    _state_class=FrontierStateForFuzzTesting,
)

# HOMESTEAD
HomesteadComputationForFuzzTesting = HomesteadComputation.configure(
    __name__='HomesteadComputationForFuzzTesting',
    apply_computation=fuzz_apply_computation,
)
HomesteadStateForFuzzTesting = HomesteadState.configure(
    __name__='HomesteadStateForFuzzTesting',
    get_ancestor_hash=get_block_hash_for_testing,
    computation_class=HomesteadComputationForFuzzTesting,
    account_db_class=EmulatorAccountDB,
)
HomesteadVMForFuzzTesting = MainnetHomesteadVM.configure(
    __name__='HomesteadVMForFuzzTesting',
    _state_class=HomesteadStateForFuzzTesting,
)

# TANGERINE WHISTLE
TangerineWhistleComputationForFuzzTesting = TangerineWhistleComputation.configure(
    __name__='TangerineWhistleComputationForFuzzTesting',
    apply_computation=fuzz_apply_computation,
)
TangerineWhistleStateForFuzzTesting = TangerineWhistleState.configure(
    __name__='TangerineWhistleStateForFuzzTesting',
    get_ancestor_hash=get_block_hash_for_testing,
    computation_class=TangerineWhistleComputationForFuzzTesting,
    account_db_class=EmulatorAccountDB,
)
TangerineWhistleVMForFuzzTesting = TangerineWhistleVM.configure(
    __name__='TangerineWhistleVMForFuzzTesting',
    _state_class=TangerineWhistleStateForFuzzTesting,
)

# SPURIOUS DRAGON
SpuriousDragonComputationForFuzzTesting = SpuriousDragonComputation.configure(
    __name__='SpuriousDragonComputationForFuzzTesting',
    apply_computation=fuzz_apply_computation,
)
SpuriousDragonStateForFuzzTesting = SpuriousDragonState.configure(
    __name__='SpuriousDragonStateForFuzzTesting',
    get_ancestor_hash=get_block_hash_for_testing,
    computation_class=SpuriousDragonComputationForFuzzTesting,
    account_db_class=EmulatorAccountDB,
)
SpuriousDragonVMForFuzzTesting = SpuriousDragonVM.configure(
    __name__='SpuriousDragonVMForFuzzTesting',
    _state_class=SpuriousDragonStateForFuzzTesting,
)

# BYZANTIUM
ByzantiumComputationForFuzzTesting = ByzantiumComputation.configure(
    __name__='ByzantiumComputationForFuzzTesting',
    apply_computation=fuzz_apply_computation,
)
ByzantiumStateForFuzzTesting = ByzantiumState.configure(
    __name__='ByzantiumStateForFuzzTesting',
    get_ancestor_hash=get_block_hash_for_testing,
    computation_class=ByzantiumComputationForFuzzTesting,
    account_db_class=EmulatorAccountDB,
)
ByzantiumVMForFuzzTesting = ByzantiumVM.configure(
    __name__='ByzantiumVMForFuzzTesting',
    _state_class=ByzantiumStateForFuzzTesting,
)

# PETERSBURG
PetersburgComputationForFuzzTesting = PetersburgComputation.configure(
    __name__='PetersburgComputationForFuzzTesting',
    apply_computation=fuzz_apply_computation,
)
PetersburgStateForFuzzTesting = PetersburgState.configure(
    __name__='PetersburgStateForFuzzTesting',
    get_ancestor_hash=get_block_hash_for_testing,
    computation_class=PetersburgComputationForFuzzTesting,
    account_db_class=EmulatorAccountDB,
)
PetersburgVMForFuzzTesting = PetersburgVM.configure(
    __name__='PetersburgVMForFuzzTesting',
    _state_class=PetersburgStateForFuzzTesting,
)
