#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import copy
import json
import traceback
import collections

from z3 import *
from utils import settings
from utils.utils import convert_stack_value_to_hex, convert_stack_value_to_int, is_fixed


BIT_VEC_VAL_ZERO = BitVecVal(0, 256)
BIT_VEC_VAL_ONE = BitVecVal(1, 256)

def print_stack(stack):
    string = "["
    for element in stack:
        if element != False:
            string += " " + str(element) + " "
        else:
            string += " False "
    string += "]"
    print(string)

def print_memory(memory):
    sorted_memory = collections.OrderedDict(sorted(memory.items()))
    for address in sorted_memory:
        print(str(address) + ": " + str(sorted_memory[address]))

def print_storage(storage):
    for address in storage:
        print(str(address) + ": {")
        for index in storage[address].keys():
            print("\t" + str(index) + ": " + str(storage[address][index]))
        print("}")

class TaintRecord:
    def __init__(self, input={}, value=False, output=False, address=None):
        """ Builds a taint record """
        # Execution environment
        self.input = input
        self.value = value
        self.output = output
        self.address = address
        # Machine state
        self.stack = []
        self.memory = {}

    def __str__(self):
        return json.dumps(self.__dict__)

    def clone(self):
        """ Clones this record"""
        clone = TaintRecord()
        clone.input   = self.input
        clone.value   = self.value
        clone.output  = self.output
        clone.address = self.address
        clone.stack   = self.stack[:]
        clone.memory  = self.memory
        return clone

class SymbolicTaintAnalyzer:
    visited_pcs = set()

    def __init__(self):
        # Machine state
        self.callstack = []
        # World state
        self.storage = {}

    def propagate_taint(self, instruction, address):
        if not instruction["error"]:
            if len(self.callstack) < instruction["depth"]:
                self.callstack.append([])

            records = self.callstack[instruction["depth"] - 1]

            if len(records) == 0:
                previous_records = self.callstack[instruction["depth"] - 2]
                if len(previous_records) > 0:
                    previous_record = previous_records[-1]
                    records.append(TaintRecord(input=previous_record.input, value=previous_record.value,
                                               output=previous_record.output, address=previous_record.address))
                else:
                    records.append(TaintRecord(address=address))

            new_record = SymbolicTaintAnalyzer.execute_instruction(records[-1], self.storage, instruction)
            records.append(new_record)

            if len(self.callstack) > instruction["depth"]:
                self.callstack[instruction["depth"]] = []

    def introduce_taint(self, taint, instruction):
        if not instruction["error"] and instruction["depth"] - 1 < len(self.callstack):
            records = self.callstack[instruction["depth"] - 1]

            mutator = SymbolicTaintAnalyzer.stack_taint_table[instruction["op"]]
            for i in range(1, mutator[1] + 1):
                if not records[-1].stack[-i]:
                    records[-1].stack[-i] = [taint]
                else:
                    record = list(records[-1].stack[-i])
                    if not taint in record:
                        record.insert(0, taint)
                    records[-1].stack[-i] = record

            if instruction["op"] in ["CALL", "CALLCODE", "DELEGATECALL", "STATICCALL"]:
                if not records[-1].output:
                    records[-1].output = []
                records[-1].output += [taint]
            elif instruction["op"] == "CALLDATACOPY":
                records[-1].memory[convert_stack_value_to_int(instruction["stack"][-1])] = []
                records[-1].memory[convert_stack_value_to_int(instruction["stack"][-1])].append(taint)

    def check_taint(self, instruction, source=None):
        if not instruction["error"] and instruction["depth"] - 1 < len(self.callstack):
            records = self.callstack[instruction["depth"] - 1]
            if len(records) < 2:
                return None
            mutator = SymbolicTaintAnalyzer.stack_taint_table[instruction["op"]]
            values = []
            for i in range(0, mutator[0]):
                if not records[-2].stack:
                    break
                if i + 1 < len(records[-2].stack):
                    record = records[-2].stack[-(i + 1)]
                    if instruction["op"] in SymbolicTaintAnalyzer.memory_access:
                        if not i in SymbolicTaintAnalyzer.memory_access[instruction["op"]]:
                            if record:
                                values += record
                    else:
                        if record:
                            values += record
            if instruction["op"] in SymbolicTaintAnalyzer.memory_access :
                mutator = SymbolicTaintAnalyzer.memory_access[instruction["op"]]
                offset = convert_stack_value_to_int(instruction["stack"][-(mutator[0] + 1)])
                size = convert_stack_value_to_int(instruction["stack"][-(mutator[1] + 1)])
                taint = SymbolicTaintAnalyzer.extract_taint_from_memory(records[-2].memory, offset, size)
                if taint:
                    values += taint
            if source:
                for value in values:
                    if value == source:
                        return records[-2]
            else:
                if values:
                    return records[-2]
            return None

    def clear_callstack(self):
        self.callstack = []
        SymbolicTaintAnalyzer.visited_pcs = set()

    def clear_storage(self):
        self.storage = {}

    def set_tainted_record(self, record, depth=-1, index=-1):
        self.callstack[depth][index] = record

    def get_tainted_record(self, depth=-1, index=-1):
        try:
            return self.callstack[depth][index]
        except:
            return None

    @staticmethod
    def execute_instruction(record, storage, instruction):
        assert len(record.stack) == len(instruction["stack"])

        new_record = record.clone()
        op = instruction["op"]

        if op.startswith("PUSH"):
            SymbolicTaintAnalyzer.mutate_push(new_record)
        elif op.startswith("DUP"):
            SymbolicTaintAnalyzer.mutate_dup(new_record, op)
        elif op.startswith("SWAP"):
            SymbolicTaintAnalyzer.mutate_swap(new_record, op)
        elif op == "MLOAD":
            SymbolicTaintAnalyzer.mutate_mload(new_record, instruction)
        elif op.startswith("MSTORE"):
            SymbolicTaintAnalyzer.mutate_mstore(new_record, instruction)
        elif op == "SLOAD":
            SymbolicTaintAnalyzer.mutate_sload(new_record, storage, instruction)
        elif op == "SSTORE":
            SymbolicTaintAnalyzer.mutate_sstore(new_record, storage, instruction)
        elif op.startswith("LOG"):
            SymbolicTaintAnalyzer.mutate_log(new_record, op)
        elif op == "SHA3":
            SymbolicTaintAnalyzer.mutate_sha3(new_record, instruction)
        elif op == "CALLVALUE":
            SymbolicTaintAnalyzer.mutate_call_value(new_record, instruction)
        elif op == "CALLDATALOAD":
            SymbolicTaintAnalyzer.mutate_call_data_load(new_record, instruction)
        elif op in ("CALLDATACOPY", "CODECOPY", "RETURNDATACOPY", "EXTCODECOPY"):
            SymbolicTaintAnalyzer.mutate_copy(new_record, op, instruction)
        elif op in ("CREATE", "CREATE2"):
            SymbolicTaintAnalyzer.mutate_create(new_record, instruction)
        elif op in ("CALL", "CALLCODE", "DELEGATECALL", "STATICCALL"):
            SymbolicTaintAnalyzer.mutate_call(new_record, op, instruction)
        elif op == "RETURNDATASIZE":
            SymbolicTaintAnalyzer.mutate_return_data_size(new_record, op, instruction)
        elif op in SymbolicTaintAnalyzer.stack_taint_table.keys():
            mutator = SymbolicTaintAnalyzer.stack_taint_table[op]
            SymbolicTaintAnalyzer.mutate_stack_symbolically(new_record, mutator, instruction)
        else:
            print("Unknown operation encountered: {}".format(op))

        return new_record

    @staticmethod
    #@profile
    def mutate_stack_symbolically(record, mutator, instruction):
        if instruction["op"] in [
            # Arithmetic Operations
            "ADD", "MUL", "SUB", "DIV", "SDIV", "MOD", "SMOD", "ADDMOD", "MULMOD", "EXP", "SHL", "SHR", "SAR",
            # Comparison Operations
            "LT", "GT", "SLT", "SGT", "EQ", "ISZERO",
            #  Bitwise Logic Operations
            "AND", "OR", "XOR", "NOT"]:

            # Detect loops
            if instruction["pc"] not in SymbolicTaintAnalyzer.visited_pcs:
                SymbolicTaintAnalyzer.visited_pcs.add(instruction["pc"])
            else:
                for i in range(mutator[0]):
                    record.stack.pop()
                record.stack.append(False)
                return

            # First Operand
            op1 = None
            if mutator[0] > 0:
                if record.stack[-1]:
                    op1 = simplify(record.stack[-1][0])
                else:
                    op1 = BitVecVal(convert_stack_value_to_int(instruction["stack"][-1]), 256)

            # Second Operand
            op2 = None
            if mutator[0] > 1:
                if record.stack[-2]:
                    op2 = simplify(record.stack[-2][0])
                else:
                    op2 = BitVecVal(convert_stack_value_to_int(instruction["stack"][-2]), 256)

            # Third Operand
            op3 = None
            if mutator[0] > 2:
                if record.stack[-3]:
                    op3 = simplify(record.stack[-3][0])
                else:
                    op3 = BitVecVal(convert_stack_value_to_int(instruction["stack"][-3]), 256)

            # Check if at least one of the operands is a symbolic expression
            if record and ((is_expr(op1) and record.stack[-1]) or (is_expr(op2) and record.stack[-2]) or (is_expr(op3) and record.stack[-3])):

                # Pop old values from stack
                for i in range(mutator[0]):
                    record.stack.pop()

                # Push new symbolic expression to stack
                # Arithmetic Operations
                if instruction["op"] == "ADD":
                    if   is_fixed(op1) and op1.as_long() == 0:
                        record.stack.append([op2])
                    elif is_fixed(op2) and op2.as_long() == 0:
                        record.stack.append([op1])
                    else:
                        record.stack.append([op1 + op2])
                elif instruction["op"] == "MUL":
                    if (is_fixed(op1) and op1.as_long() == 0) or \
                       (is_fixed(op2) and op2.as_long() == 0):
                        record.stack.append([BIT_VEC_VAL_ZERO])
                    else:
                        record.stack.append([op1 * op2])
                elif instruction["op"] == "SUB":
                    record.stack.append([op1 - op2])
                elif instruction["op"] == "DIV":
                    if (is_fixed(op1) and op1.as_long() == 0) or \
                       (is_fixed(op2) and op2.as_long() == 0):
                        record.stack.append([BIT_VEC_VAL_ZERO])
                    else:
                        record.stack.append([UDiv(op1, op2)])
                elif instruction["op"] == "SDIV":
                    if (is_fixed(op1) and op1.as_long() == 0) or \
                       (is_fixed(op2) and op2.as_long() == 0):
                        record.stack.append([BIT_VEC_VAL_ZERO])
                    else:
                        record.stack.append([op1 / op2])
                elif instruction["op"] == "MOD":
                    record.stack.append([BIT_VEC_VAL_ZERO if op2 == 0 else URem(op1, op2)])
                elif instruction["op"] == "SMOD":
                    record.stack.append([BIT_VEC_VAL_ZERO if op2 == 0 else SRem(op1, op2)])
                elif instruction["op"] == "ADDMOD":
                    record.stack.append([URem(URem(op1, op3) + URem(op2, op3), op3)])
                elif instruction["op"] == "MULMOD":
                    record.stack.append([URem(URem(op1, op3) * URem(op2, op3), op3)])
                elif instruction["op"] == "EXP":
                    if is_bv_value(op1) and is_bv_value(op2):
                        record.stack.append([BitVecVal(pow(op1.as_long(), op2.as_long(), 2 ** 256), 256)])
                    else:
                        record.stack.append(False)
                elif instruction["op"] == "SHL":
                    record.stack.append([op1 << op2])
                elif instruction["op"] == "SHR":
                    record.stack.append([LShR(op1, op2)])
                elif instruction["op"] == "SAR":
                    record.stack.append([op1 >> op2])

                # Comparison Operations
                elif instruction["op"] == "LT":
                    record.stack.append([If(ULT(op1, op2), BIT_VEC_VAL_ONE, BIT_VEC_VAL_ZERO)])
                elif instruction["op"] == "GT":
                    record.stack.append([If(UGT(op1, op2), BIT_VEC_VAL_ONE, BIT_VEC_VAL_ZERO)])
                elif instruction["op"] == "SLT":
                    record.stack.append([If(op1 < op2, BIT_VEC_VAL_ONE, BIT_VEC_VAL_ZERO)])
                elif instruction["op"] == "SGT":
                    record.stack.append([If(op1 > op2, BIT_VEC_VAL_ONE, BIT_VEC_VAL_ZERO)])
                elif instruction["op"] == "EQ":
                    record.stack.append([If(op1 == op2, BIT_VEC_VAL_ONE, BIT_VEC_VAL_ZERO)])
                elif instruction["op"] == "ISZERO":
                    record.stack.append([If(op1 == 0, BIT_VEC_VAL_ONE, BIT_VEC_VAL_ZERO)])

                #  Bitwise Logic Operations
                elif instruction["op"] == "AND":
                    if (is_fixed(op1) and op1.as_long() == 0) or \
                       (is_fixed(op2) and op2.as_long() == 0):
                        record.stack.append([BIT_VEC_VAL_ZERO])
                    else:
                        record.stack.append([op1 & op2])
                elif instruction["op"] == "OR":
                    record.stack.append([op1 | op2])
                elif instruction["op"] == "XOR":
                    if   is_fixed(op1) and op1.as_long() == 0:
                        record.stack.append([op2])
                    elif is_fixed(op2) and op2.as_long() == 0:
                        record.stack.append([op1])
                    else:
                        record.stack.append([op1 ^ op2])
                elif instruction["op"] == "NOT":
                    record.stack.append([~op1])
            else:
                SymbolicTaintAnalyzer.mutate_stack(record, mutator)
        else:
            SymbolicTaintAnalyzer.mutate_stack(record, mutator)

    @staticmethod
    def mutate_stack(record, mutator):
        taint = False
        for i in range(mutator[0]):
            values = record.stack.pop()
            if values != False:
                if taint == False:
                    taint = []
                for j in range(len(values)):
                    if not values[j] in taint:
                        taint.append(values[j])
        for i in range(mutator[1]):
            record.stack.append(taint)

    @staticmethod
    def get_operand(record, instruction, index):
        if record.stack[-1]:
            return simplify(record.stack[-index][0])
        return BitVecVal(convert_stack_value_to_int(instruction["stack"][-index]), 256)

    @staticmethod
    def mutate_push(record):
        SymbolicTaintAnalyzer.mutate_stack(record, (0, 1))

    @staticmethod
    def mutate_dup(record, op):
        depth = int(op[3:])
        index = len(record.stack) - depth
        record.stack.append(record.stack[index])

    @staticmethod
    def mutate_swap(record, op):
        depth = int(op[4:])
        l = len(record.stack) - 1
        i = l - depth
        record.stack[l], record.stack[i] = record.stack[i], record.stack[l]

    @staticmethod
    def mutate_mload(record, instruction):
        record.stack.pop()
        index = convert_stack_value_to_int(instruction["stack"][-1])
        record.stack.append(SymbolicTaintAnalyzer.extract_taint_from_memory(record.memory, index, 32))

    @staticmethod
    def mutate_mstore(record, instruction):
        record.stack.pop()
        index, value = convert_stack_value_to_int(instruction["stack"][-1]), record.stack.pop()
        record.memory[index] = value
        record.memory = collections.OrderedDict(sorted(record.memory.items()))

    @staticmethod
    def mutate_sload(record, storage, instruction):
        record.stack.pop()
        taint = False
        index = convert_stack_value_to_hex(instruction["stack"][-1])
        if record.address in storage:
            if index in storage[record.address].keys() and storage[record.address][index]:
                if not taint:
                    taint = storage[record.address][index]
                else:
                    taint += storage[record.address][index]
        record.stack.append(taint)

    @staticmethod
    def mutate_sstore(record, storage, instruction):
        record.stack.pop()
        index, value = convert_stack_value_to_hex(instruction["stack"][-1]), record.stack.pop()
        if not record.address in storage:
            storage[record.address] = {}
        storage[record.address][index] = value

    @staticmethod
    def mutate_log(record, op):
        depth = int(op[3:])
        for _ in range(depth + 2):
            record.stack.pop()

    @staticmethod
    def mutate_sha3(record, instruction):
        record.stack.pop()
        offset = convert_stack_value_to_int(instruction["stack"][-1])
        record.stack.pop()
        size = convert_stack_value_to_int(instruction["stack"][-2])
        value = SymbolicTaintAnalyzer.extract_taint_from_memory(record.memory, offset, size)
        record.stack.append(value)

    @staticmethod
    def mutate_call_data_load(record, instruction):
        value = record.stack.pop()
        if record.input:
            index = convert_stack_value_to_hex(instruction["stack"][-1])
            if index in record.input:
                if not value:
                    value = record.input[index]
                else:
                    value += record.input[index]
        record.stack.append(value)

    @staticmethod
    def mutate_call_value(record, instruction):
        record.stack.append(record.value)

    @staticmethod
    def mutate_copy(record, op, instruction):
        if op == "EXTCODECOPY":
            record.stack.pop()
            index = convert_stack_value_to_int(instruction["stack"][-2])
        else:
            index = convert_stack_value_to_int(instruction["stack"][-1])
        record.stack.pop()
        record.stack.pop()
        record.memory[index] = record.stack.pop()
        record.memory = collections.OrderedDict(sorted(record.memory.items()))


    @staticmethod
    def mutate_create(record, instruction):
        record.stack.pop()
        record.stack.pop()
        record.stack.pop()
        record.stack.append(False)

    @staticmethod
    def mutate_call(record, op, instruction):
        record.stack.pop()
        record.stack.pop()
        if op in ["CALL", "CALLCODE"]:
            record.stack.pop()
        record.stack.pop()
        record.stack.pop()
        record.stack.pop()
        record.stack.pop()
        record.stack.append(False)
        record.input = False
        record.value = False
        record.output = False

    @staticmethod
    def mutate_return_data_size(record, op, instruction):
        record.stack.append(record.output)

    @staticmethod
    def extract_taint_from_memory(memory, offset, size):
        taint = []
        keys = list(memory.keys())
        for j in range(len(keys)):
            if int(keys[j]) >= offset + size:
                break
            if offset <= int(keys[j]):
                if memory[keys[j]]:
                    for k in memory[keys[j]]:
                        if not k in taint:
                            taint.append(k)
        if not taint:
            taint = False
        return taint

    memory_access = {
        # instruction: (memory offset, memory size)
        'SHA3': (0, 1),
        'LOG0': (0, 1),
        'LOG1': (0, 1),
        'LOG2': (0, 1),
        'LOG3': (0, 1),
        'LOG4': (0, 1),
        'CREATE': (1, 2),
        'CREATE2': (1, 2),
        'CALL': (3, 4),
        'CALLCODE': (3, 4),
        'RETURN': (0, 1),
        'DELEGATECALL': (2, 3),
        'STATICCALL': (2, 3)
    }

    stack_taint_table = {
        # instruction: (taint source, taint target)
        # 0s: Stop and Arithmetic Operations
        'STOP': (0, 0),
        'ADD': (2, 1),
        'MUL': (2, 1),
        'SUB': (2, 1),
        'DIV': (2, 1),
        'SDIV': (2, 1),
        'MOD': (2, 1),
        'SMOD': (2, 1),
        'ADDMOD': (3, 1),
        'MULMOD': (3, 1),
        'EXP': (2, 1),
        'SIGNEXTEND': (2, 1),
        # 10s: Comparison & Bitwise Logic Operations
        'LT': (2, 1),
        'GT': (2, 1),
        'SLT': (2, 1),
        'SGT': (2, 1),
        'EQ': (2, 1),
        'ISZERO': (1, 1),
        'AND': (2, 1),
        'OR': (2, 1),
        'XOR': (2, 1),
        'NOT': (1, 1),
        'BYTE': (2, 1),
        'SHL': (2, 1),
        'SHR': (2, 1),
        'SAR': (2, 1),
        # 20s: SHA3
        'SHA3': (2, 1),
        # 30s: Environmental Information
        'ADDRESS': (0, 1),
        'BALANCE': (1, 1),
        'ORIGIN': (0, 1),
        'CALLER': (0, 1),
        'CALLVALUE': (0, 1),
        'CALLDATALOAD': (1, 1),
        'CALLDATASIZE': (0, 1),
        'CALLDATACOPY': (3, 0),
        'CODESIZE': (0, 1),
        'CODECOPY': (3, 0),
        'GASPRICE': (0, 1),
        'EXTCODESIZE': (1, 1),
        'EXTCODECOPY': (4, 0),
        'RETURNDATASIZE': (0, 1),
        'RETURNDATACOPY': (3, 0),
        'EXTCODEHASH': (1, 1),
        # 40s: Block Information
        'BLOCKHASH': (1, 1),
        'COINBASE': (0, 1),
        'TIMESTAMP': (0, 1),
        'NUMBER': (0, 1),
        'DIFFICULTY': (0, 1),
        'GASLIMIT': (0, 1),
        # 50s: Stack, Memory, Storage and Flow Operations
        'POP': (1, 0),
        'MLOAD': (1, 1),
        'MSTORE': (2, 0),
        'MSTORE8': (2, 0),
        'SLOAD': (1, 1),
        'SSTORE': (2, 0),
        'JUMP': (1, 0),
        'JUMPI': (2, 0),
        'PC': (0, 1),
        'MSIZE': (0, 1),
        'GAS': (0, 1),
        'JUMPDEST': (0, 0),
        # 60s & 70s: Push Operations
        'PUSH1': (0, 1),
        'PUSH2': (0, 1),
        'PUSH3': (0, 1),
        'PUSH4': (0, 1),
        'PUSH5': (0, 1),
        'PUSH6': (0, 1),
        'PUSH7': (0, 1),
        'PUSH8': (0, 1),
        'PUSH9': (0, 1),
        'PUSH10': (0, 1),
        'PUSH11': (0, 1),
        'PUSH12': (0, 1),
        'PUSH13': (0, 1),
        'PUSH14': (0, 1),
        'PUSH15': (0, 1),
        'PUSH16': (0, 1),
        'PUSH17': (0, 1),
        'PUSH18': (0, 1),
        'PUSH19': (0, 1),
        'PUSH20': (0, 1),
        'PUSH21': (0, 1),
        'PUSH22': (0, 1),
        'PUSH23': (0, 1),
        'PUSH24': (0, 1),
        'PUSH25': (0, 1),
        'PUSH26': (0, 1),
        'PUSH27': (0, 1),
        'PUSH28': (0, 1),
        'PUSH29': (0, 1),
        'PUSH30': (0, 1),
        'PUSH31': (0, 1),
        'PUSH32': (0, 1),
        # 80s: Duplication Operations
        'DUP1': (1, 2),
        'DUP2': (2, 3),
        'DUP3': (3, 4),
        'DUP4': (4, 5),
        'DUP5': (5, 6),
        'DUP6': (6, 7),
        'DUP7': (7, 8),
        'DUP8': (8, 9),
        'DUP9': (9, 10),
        'DUP10': (10, 11),
        'DUP11': (11, 12),
        'DUP12': (12, 13),
        'DUP13': (13, 14),
        'DUP14': (14, 15),
        'DUP15': (15, 16),
        'DUP16': (16, 17),
        # 90s: Exchange Operations
        'SWAP1': (2, 2),
        'SWAP2': (3, 3),
        'SWAP3': (4, 4),
        'SWAP4': (5, 5),
        'SWAP5': (6, 6),
        'SWAP6': (7, 7),
        'SWAP7': (8, 8),
        'SWAP8': (9, 9),
        'SWAP9': (10, 10),
        'SWAP10': (11, 11),
        'SWAP11': (12, 12),
        'SWAP12': (13, 13),
        'SWAP13': (14, 14),
        'SWAP14': (15, 15),
        'SWAP15': (16, 16),
        'SWAP16': (17, 17),
        # a0s: Logging Operations
        'LOG0': (2, 0),
        'LOG1': (3, 0),
        'LOG2': (4, 0),
        'LOG3': (5, 0),
        'LOG4': (6, 0),
        # f0s: System Operations
        'CREATE': (3, 1),
        'CREATE2': (3, 1),
        'CALL': (7, 1),
        'CALLCODE': (7, 1),
        'RETURN': (2, 0),
        'DELEGATECALL': (6, 1),
        'STATICCALL': (6, 1),
        'REVERT': (2, 0),
        'INVALID': (0, 0),
        'SELFDESTRUCT': (1, 0)
    }
