#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import subprocess

from .utils import remove_swarm_hash, convert_stack_value_to_int

class BasicBlock:
    def __init__(self):
        self.start_address    = None
        self.end_address      = None
        self.instructions     = {}

    def __str__(self):
        string  = "---------Basic Block---------\n"
        string += "Start address: %d (0x%x)\n" % ((self.start_address, self.start_address) if self.start_address else (0, 0))
        string += "End address: %d (0x%x)\n" % ((self.end_address, self.end_address) if self.end_address else (0, 0))
        string += "Instructions: "+str(self.instructions)+"\n"
        string += "-----------------------------"
        return string

    def __hash__(self):
        return hash(str(self))

    def __eq__(self, _other):
        return self.__dict__ == _other.__dict__

    def set_start_address(self, start_address):
        self.start_address = start_address

    def get_start_address(self):
        return self.start_address

    def set_end_address(self, end_address):
        self.end_address = end_address

    def get_end_address(self):
        return self.end_address

    def add_instruction(self, key, value):
        self.instructions[key] = value

    def get_instructions(self):
        return self.instructions

class ControlFlowGraph:
    def __init__(self):
        self.edges = {}
        self.vertices = {}
        self.visited_pcs = set()
        self.visited_branches = {}
        self.error_pcs = set()
        self.can_send_ether = False

    def build(self, bytecode, evm_version):
        bytecode = bytes.fromhex(remove_swarm_hash(bytecode).replace("0x", ""))
        current_pc = 0
        previous_pc = 0
        basic_block = None
        previous_opcode = None
        previous_push_value = None
        while current_pc < len(bytecode):
            opcode = bytecode[current_pc]

            if opcode in self.opcode_to_mnemonic[evm_version] and self.opcode_to_mnemonic[evm_version][opcode] in ["CREATE", "CALL", "DELEGATECALL", "SELFDESTRUCT", "SUICIDE"]:
                self.can_send_ether = True

            if previous_opcode == 255: # SELFDESTRUCT
                basic_block.set_end_address(previous_pc)
                self.vertices[current_pc] = basic_block
                basic_block = None

            if basic_block is None:
                basic_block = BasicBlock()
                basic_block.set_start_address(current_pc)

            if opcode == 91 and basic_block.get_instructions(): # JUMPDEST
                basic_block.set_end_address(previous_pc)
                if previous_pc not in self.edges and previous_opcode not in [0, 86, 87, 243, 253, 254, 255]: # Terminating/Conditional: STOP, JUMP, JUMPI, RETURN, REVERT, INVALID, SELFDESTRUCT
                    self.edges[previous_pc] = []
                    self.edges[previous_pc].append(current_pc)
                self.vertices[current_pc] = basic_block
                basic_block = BasicBlock()
                basic_block.set_start_address(current_pc)

            if opcode < 96 or opcode > 127: # PUSH??
                if opcode in self.opcode_to_mnemonic[evm_version]:
                    basic_block.add_instruction(current_pc, self.opcode_to_mnemonic[evm_version][opcode])
                else:
                    basic_block.add_instruction(current_pc, "Missing opcode "+hex(opcode))

            if opcode == 86 or opcode == 87: # JUMP or JUMPI
                basic_block.set_end_address(current_pc)
                self.vertices[current_pc] = basic_block
                basic_block = None
                if opcode == 86 and previous_opcode and previous_opcode >= 96 and previous_opcode <= 127:
                    if current_pc not in self.edges:
                        self.edges[current_pc] = []
                    self.edges[current_pc].append(previous_push_value)
                if opcode == 87:
                    if current_pc not in self.edges:
                        self.edges[current_pc] = []
                    self.edges[current_pc].append(current_pc+1)
                    if previous_opcode and previous_opcode >= 96 and previous_opcode <= 127:
                        if current_pc not in self.edges:
                            self.edges[current_pc] = []
                        self.edges[current_pc].append(previous_push_value)

            previous_pc = current_pc
            if opcode >= 96 and opcode <= 127: # PUSH??
                size = opcode - 96 + 1
                previous_push_value = ""
                for i in range(size):
                    try:
                        previous_push_value += str(hex(bytecode[current_pc+i+1])).replace("0x", "").zfill(2)
                    except Exception as e:
                        pass
                if previous_push_value:
                    previous_push_value = "0x" + previous_push_value
                    basic_block.add_instruction(current_pc, self.opcode_to_mnemonic[evm_version][opcode]+" "+previous_push_value)
                    previous_push_value = int(previous_push_value, 16)
                    current_pc += size

            current_pc += 1
            previous_opcode = opcode

        if basic_block:
            basic_block.set_end_address(previous_pc)
            self.vertices[current_pc] = basic_block

    def execute(self, pc, stack, mnemonic, visited_branches, error_pcs):
        if mnemonic == "JUMP":
            if pc not in self.edges:
                self.edges[pc] = []
            if convert_stack_value_to_int(stack[-1]) not in self.edges[pc]:
                self.edges[pc].append(convert_stack_value_to_int(stack[-1]))
        self.visited_pcs.add(pc)
        self.visited_branches = visited_branches
        self.error_pcs = error_pcs

    def save_control_flow_graph(self, filename, extension):
        f = open(filename+'.dot', 'w')
        f.write('digraph confuzzius_cfg {\n')
        f.write('rankdir = TB;\n')
        f.write('size = "240"\n')
        f.write('graph[fontname = Courier, fontsize = 14.0, labeljust = l, nojustify = true];node[shape = record];\n')
        address_width = 10
        for basic_block in self.vertices.values():
            if len(hex(list(basic_block.get_instructions().keys())[-1])) > address_width:
                address_width = len(hex(list(basic_block.get_instructions().keys())[-1]))
        for basic_block in self.vertices.values():
            # Draw vertices
            label = '"'+hex(basic_block.get_start_address())+'"[label="'
            for address in basic_block.get_instructions():
                label += "{0:#0{1}x}".format(address, address_width)+" "+basic_block.get_instructions()[address]+"\l"
            visited_basic_block = False
            for pc in self.error_pcs:
                if pc in basic_block.get_instructions().keys():
                    f.write(label+'",style=filled,fillcolor=red];\n')
                    visited_basic_block = True
                    break
            if not visited_basic_block:
                if  basic_block.get_start_address() in self.visited_pcs and basic_block.get_end_address() in self.visited_pcs:
                    f.write(label+'",style=filled,fillcolor=gray];\n')
                else:
                    f.write(label+'",style=filled,fillcolor=white];\n')
            # Draw edges
            if basic_block.get_end_address() in self.edges:
                # JUMPI
                if list(basic_block.get_instructions().values())[-1] == "JUMPI":
                    if hex(basic_block.get_end_address()) in self.visited_branches and 0 in self.visited_branches[hex(basic_block.get_end_address())] and self.visited_branches[hex(basic_block.get_end_address())][0]["expression"]:
                        f.write('"'+hex(basic_block.get_start_address())+'" -> "'+hex(self.edges[basic_block.get_end_address()][0])+'" [label=" '+str(self.visited_branches[hex(basic_block.get_end_address())][0]["expression"][-1])+'",color="red"];\n')
                    else:
                        f.write('"'+hex(basic_block.get_start_address())+'" -> "'+hex(self.edges[basic_block.get_end_address()][0])+'" [label="",color="red"];\n')
                    if hex(basic_block.get_end_address()) in self.visited_branches and 1 in self.visited_branches[hex(basic_block.get_end_address())] and self.visited_branches[hex(basic_block.get_end_address())][1]["expression"]:
                        f.write('"'+hex(basic_block.get_start_address())+'" -> "'+hex(self.edges[basic_block.get_end_address()][1])+'" [label=" '+str(self.visited_branches[hex(basic_block.get_end_address())][1]["expression"][-1])+'",color="green"];\n')
                    else:
                        f.write('"'+hex(basic_block.get_start_address())+'" -> "'+hex(self.edges[basic_block.get_end_address()][1])+'" [label="",color="green"];\n')
                # Other instructions
                else:
                    for i in range(len(self.edges[basic_block.get_end_address()])):
                        f.write('"'+hex(basic_block.get_start_address())+'" -> "'+hex(self.edges[basic_block.get_end_address()][i])+'" [label="",color="black"];\n')
        f.write('}\n')
        f.close()
        if not subprocess.call('dot '+filename+'.dot -T'+extension+' -o '+filename+'.'+extension, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0:
            print("Graphviz is not available. Please install Graphviz from https://www.graphviz.org/download/.")
        else:
            os.remove(filename+".dot")

    opcode_to_mnemonic = {
        'homestead': {
            # 0s: Stop and Arithmetic Operations
              0: 'STOP',
              1: 'ADD',
              2: 'MUL',
              3: 'SUB',
              4: 'DIV',
              5: 'SDIV',
              6: 'MOD',
              7: 'SMOD',
              8: 'ADDMOD',
              9: 'MULMOD',
             10: 'EXP',
             11: 'SIGNEXTEND',
            # 10s: Comparison & Bitwise Logic Operations
             16: 'LT',
             17: 'GT',
             18: 'SLT',
             19: 'SGT',
             20: 'EQ',
             21: 'ISZERO',
             22: 'AND',
             23: 'OR',
             24: 'XOR',
             25: 'NOT',
             26: 'BYTE',
            # 20s: SHA3
             32: 'SHA3',
            # 30s: Environmental Information
             48: 'ADDRESS',
             49: 'BALANCE',
             50: 'ORIGIN',
             51: 'CALLER',
             52: 'CALLVALUE',
             53: 'CALLDATALOAD',
             54: 'CALLDATASIZE',
             55: 'CALLDATACOPY',
             56: 'CODESIZE',
             57: 'CODECOPY',
             58: 'GASPRICE',
             59: 'EXTCODESIZE',
             60: 'EXTCODECOPY',
            # 40s: Block Information
             64: 'BLOCKHASH',
             65: 'COINBASE',
             66: 'TIMESTAMP',
             67: 'NUMBER',
             68: 'DIFFICULTY',
             69: 'GASLIMIT',
            # 50s: Stack, Memory, Storage and Flow Operations
             80: 'POP',
             81: 'MLOAD',
             82: 'MSTORE',
             83: 'MSTORE8',
             84: 'SLOAD',
             85: 'SSTORE',
             86: 'JUMP',
             87: 'JUMPI',
             88: 'PC',
             89: 'MSIZE',
             90: 'GAS',
             91: 'JUMPDEST',
            # 60s & 70s: Push Operations
             96: 'PUSH1',
             97: 'PUSH2',
             98: 'PUSH3',
             99: 'PUSH4',
            100: 'PUSH5',
            101: 'PUSH6',
            102: 'PUSH7',
            103: 'PUSH8',
            104: 'PUSH9',
            105: 'PUSH10',
            106: 'PUSH11',
            107: 'PUSH12',
            108: 'PUSH13',
            109: 'PUSH14',
            110: 'PUSH15',
            111: 'PUSH16',
            112: 'PUSH17',
            113: 'PUSH18',
            114: 'PUSH19',
            115: 'PUSH20',
            116: 'PUSH21',
            117: 'PUSH22',
            118: 'PUSH23',
            119: 'PUSH24',
            120: 'PUSH25',
            121: 'PUSH26',
            122: 'PUSH27',
            123: 'PUSH28',
            124: 'PUSH29',
            125: 'PUSH30',
            126: 'PUSH31',
            127: 'PUSH32',
            # 80s: Duplication Operations
            128: 'DUP1',
            129: 'DUP2',
            130: 'DUP3',
            131: 'DUP4',
            132: 'DUP5',
            133: 'DUP6',
            134: 'DUP7',
            135: 'DUP8',
            136: 'DUP9',
            137: 'DUP10',
            138: 'DUP11',
            139: 'DUP12',
            140: 'DUP13',
            141: 'DUP14',
            142: 'DUP15',
            143: 'DUP16',
            # 90s: Exchange Operations
            144: 'SWAP1',
            145: 'SWAP2',
            146: 'SWAP3',
            147: 'SWAP4',
            148: 'SWAP5',
            149: 'SWAP6',
            150: 'SWAP7',
            151: 'SWAP8',
            152: 'SWAP9',
            153: 'SWAP10',
            154: 'SWAP11',
            155: 'SWAP12',
            156: 'SWAP13',
            157: 'SWAP14',
            158: 'SWAP15',
            159: 'SWAP16',
            # a0s: Logging Operations
            160: 'LOG0',
            161: 'LOG1',
            162: 'LOG2',
            163: 'LOG3',
            164: 'LOG4',
            # f0s: System Operations
            240: 'CREATE',
            241: 'CALL',
            242: 'CALLCODE',
            243: 'RETURN',
            244: 'DELEGATECALL',
            254: 'ASSERTFAIL',
            255: 'SUICIDE'
        },
        'byzantium': {
            # 0s: Stop and Arithmetic Operations
              0: 'STOP',
              1: 'ADD',
              2: 'MUL',
              3: 'SUB',
              4: 'DIV',
              5: 'SDIV',
              6: 'MOD',
              7: 'SMOD',
              8: 'ADDMOD',
              9: 'MULMOD',
             10: 'EXP',
             11: 'SIGNEXTEND',
            # 10s: Comparison & Bitwise Logic Operations
             16: 'LT',
             17: 'GT',
             18: 'SLT',
             19: 'SGT',
             20: 'EQ',
             21: 'ISZERO',
             22: 'AND',
             23: 'OR',
             24: 'XOR',
             25: 'NOT',
             26: 'BYTE',
            # 20s: SHA3
             32: 'SHA3',
            # 30s: Environmental Information
             48: 'ADDRESS',
             49: 'BALANCE',
             50: 'ORIGIN',
             51: 'CALLER',
             52: 'CALLVALUE',
             53: 'CALLDATALOAD',
             54: 'CALLDATASIZE',
             55: 'CALLDATACOPY',
             56: 'CODESIZE',
             57: 'CODECOPY',
             58: 'GASPRICE',
             59: 'EXTCODESIZE',
             60: 'EXTCODECOPY',
             61: 'RETURNDATASIZE',
             62: 'RETURNDATACOPY',
            # 40s: Block Information
             64: 'BLOCKHASH',
             65: 'COINBASE',
             66: 'TIMESTAMP',
             67: 'NUMBER',
             68: 'DIFFICULTY',
             69: 'GASLIMIT',
            # 50s: Stack, Memory, Storage and Flow Operations
             80: 'POP',
             81: 'MLOAD',
             82: 'MSTORE',
             83: 'MSTORE8',
             84: 'SLOAD',
             85: 'SSTORE',
             86: 'JUMP',
             87: 'JUMPI',
             88: 'PC',
             89: 'MSIZE',
             90: 'GAS',
             91: 'JUMPDEST',
            # 60s & 70s: Push Operations
             96: 'PUSH1',
             97: 'PUSH2',
             98: 'PUSH3',
             99: 'PUSH4',
            100: 'PUSH5',
            101: 'PUSH6',
            102: 'PUSH7',
            103: 'PUSH8',
            104: 'PUSH9',
            105: 'PUSH10',
            106: 'PUSH11',
            107: 'PUSH12',
            108: 'PUSH13',
            109: 'PUSH14',
            110: 'PUSH15',
            111: 'PUSH16',
            112: 'PUSH17',
            113: 'PUSH18',
            114: 'PUSH19',
            115: 'PUSH20',
            116: 'PUSH21',
            117: 'PUSH22',
            118: 'PUSH23',
            119: 'PUSH24',
            120: 'PUSH25',
            121: 'PUSH26',
            122: 'PUSH27',
            123: 'PUSH28',
            124: 'PUSH29',
            125: 'PUSH30',
            126: 'PUSH31',
            127: 'PUSH32',
            # 80s: Duplication Operations
            128: 'DUP1',
            129: 'DUP2',
            130: 'DUP3',
            131: 'DUP4',
            132: 'DUP5',
            133: 'DUP6',
            134: 'DUP7',
            135: 'DUP8',
            136: 'DUP9',
            137: 'DUP10',
            138: 'DUP11',
            139: 'DUP12',
            140: 'DUP13',
            141: 'DUP14',
            142: 'DUP15',
            143: 'DUP16',
            # 90s: Exchange Operations
            144: 'SWAP1',
            145: 'SWAP2',
            146: 'SWAP3',
            147: 'SWAP4',
            148: 'SWAP5',
            149: 'SWAP6',
            150: 'SWAP7',
            151: 'SWAP8',
            152: 'SWAP9',
            153: 'SWAP10',
            154: 'SWAP11',
            155: 'SWAP12',
            156: 'SWAP13',
            157: 'SWAP14',
            158: 'SWAP15',
            159: 'SWAP16',
            # a0s: Logging Operations
            160: 'LOG0',
            161: 'LOG1',
            162: 'LOG2',
            163: 'LOG3',
            164: 'LOG4',
            # f0s: System Operations
            240: 'CREATE',
            241: 'CALL',
            242: 'CALLCODE',
            243: 'RETURN',
            244: 'DELEGATECALL',
            250: 'STATICCALL',
            253: 'REVERT',
            254: 'INVALID',
            255: 'SELFDESTRUCT'
        },
        'petersburg': {
            # 0s: Stop and Arithmetic Operations
              0: 'STOP',
              1: 'ADD',
              2: 'MUL',
              3: 'SUB',
              4: 'DIV',
              5: 'SDIV',
              6: 'MOD',
              7: 'SMOD',
              8: 'ADDMOD',
              9: 'MULMOD',
             10: 'EXP',
             11: 'SIGNEXTEND',
            # 10s: Comparison & Bitwise Logic Operations
             16: 'LT',
             17: 'GT',
             18: 'SLT',
             19: 'SGT',
             20: 'EQ',
             21: 'ISZERO',
             22: 'AND',
             23: 'OR',
             24: 'XOR',
             25: 'NOT',
             26: 'BYTE',
             27: 'SHL',
             28: 'SHR',
             29: 'SAR',
            # 20s: SHA3
             32: 'SHA3',
            # 30s: Environmental Information
             48: 'ADDRESS',
             49: 'BALANCE',
             50: 'ORIGIN',
             51: 'CALLER',
             52: 'CALLVALUE',
             53: 'CALLDATALOAD',
             54: 'CALLDATASIZE',
             55: 'CALLDATACOPY',
             56: 'CODESIZE',
             57: 'CODECOPY',
             58: 'GASPRICE',
             59: 'EXTCODESIZE',
             60: 'EXTCODECOPY',
             61: 'RETURNDATASIZE',
             62: 'RETURNDATACOPY',
             63: 'EXTCODEHASH',
            # 40s: Block Information
             64: 'BLOCKHASH',
             65: 'COINBASE',
             66: 'TIMESTAMP',
             67: 'NUMBER',
             68: 'DIFFICULTY',
             69: 'GASLIMIT',
             70: 'CHAINID',
             71: 'SELFBALANCE',
            # 50s: Stack, Memory, Storage and Flow Operations
             80: 'POP',
             81: 'MLOAD',
             82: 'MSTORE',
             83: 'MSTORE8',
             84: 'SLOAD',
             85: 'SSTORE',
             86: 'JUMP',
             87: 'JUMPI',
             88: 'PC',
             89: 'MSIZE',
             90: 'GAS',
             91: 'JUMPDEST',
            # 60s & 70s: Push Operations
             96: 'PUSH1',
             97: 'PUSH2',
             98: 'PUSH3',
             99: 'PUSH4',
            100: 'PUSH5',
            101: 'PUSH6',
            102: 'PUSH7',
            103: 'PUSH8',
            104: 'PUSH9',
            105: 'PUSH10',
            106: 'PUSH11',
            107: 'PUSH12',
            108: 'PUSH13',
            109: 'PUSH14',
            110: 'PUSH15',
            111: 'PUSH16',
            112: 'PUSH17',
            113: 'PUSH18',
            114: 'PUSH19',
            115: 'PUSH20',
            116: 'PUSH21',
            117: 'PUSH22',
            118: 'PUSH23',
            119: 'PUSH24',
            120: 'PUSH25',
            121: 'PUSH26',
            122: 'PUSH27',
            123: 'PUSH28',
            124: 'PUSH29',
            125: 'PUSH30',
            126: 'PUSH31',
            127: 'PUSH32',
            # 80s: Duplication Operations
            128: 'DUP1',
            129: 'DUP2',
            130: 'DUP3',
            131: 'DUP4',
            132: 'DUP5',
            133: 'DUP6',
            134: 'DUP7',
            135: 'DUP8',
            136: 'DUP9',
            137: 'DUP10',
            138: 'DUP11',
            139: 'DUP12',
            140: 'DUP13',
            141: 'DUP14',
            142: 'DUP15',
            143: 'DUP16',
            # 90s: Exchange Operations
            144: 'SWAP1',
            145: 'SWAP2',
            146: 'SWAP3',
            147: 'SWAP4',
            148: 'SWAP5',
            149: 'SWAP6',
            150: 'SWAP7',
            151: 'SWAP8',
            152: 'SWAP9',
            153: 'SWAP10',
            154: 'SWAP11',
            155: 'SWAP12',
            156: 'SWAP13',
            157: 'SWAP14',
            158: 'SWAP15',
            159: 'SWAP16',
            # a0s: Logging Operations
            160: 'LOG0',
            161: 'LOG1',
            162: 'LOG2',
            163: 'LOG3',
            164: 'LOG4',
            # f0s: System Operations
            240: 'CREATE',
            241: 'CALL',
            242: 'CALLCODE',
            243: 'RETURN',
            244: 'DELEGATECALL',
            245: 'CREATE2',
            250: 'STATICCALL',
            253: 'REVERT',
            254: 'INVALID',
            255: 'SELFDESTRUCT'
        }
    }
