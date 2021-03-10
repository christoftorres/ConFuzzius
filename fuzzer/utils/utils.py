#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import json
import shlex
import solcx
import logging
import eth_utils
import subprocess

from web3 import Web3
from .settings import LOGGING_LEVEL

def initialize_logger(name):
    logger = logging.getLogger(name)
    logger.title = lambda *a: logger.info(*[bold(x) for x in a])
    logger_error = logger.error
    logger.error = lambda *a: logger_error(*[red(bold(x)) for x in a])
    logger_warning = logger.warning
    logger.warning = lambda *a: logger_warning(*[red(bold(x)) for x in a])
    logger.setLevel(level=LOGGING_LEVEL)
    logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    return logger

def bold(x):
    return "".join(['\033[1m', x, '\033[0m']) if isinstance(x, str) else x

def red(x):
    return "".join(['\033[91m', x, '\033[0m']) if isinstance(x, str) else x

def code_bool(value: bool):
    return str(int(value)).zfill(64)

def code_uint(value):
    return hex(value).replace("0x", "").zfill(64)

def code_int(value):
    return hex(value).replace("0x", "").zfill(64)

def code_address(value):
    return value.zfill(64)

def code_bytes(value):
    return value.ljust(64, "0")

def code_type(value, type):
    if type == "bool":
        return code_bool(value)
    elif type.startswith("uint"):
        return code_uint(value)
    elif type.startswith("int"):
        return code_int(value)
    elif type == "address":
        return code_address(value)
    elif type.startswith("bytes"):
        return code_bytes(value)
    else:
        raise Exception()

def run_command(cmd):
    FNULL = open(os.devnull, 'w')
    solc_p = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=FNULL)
    return solc_p.communicate()[0]

def compile(solc_version, evm_version, source_code_file):
    out = None
    with open(source_code_file, 'r') as file:
        source_code = file.read()
        try:
            if solc_version != solcx.get_solc_version():
                solcx.set_solc_version(solc_version, True)
            out = solcx.compile_standard({
                'language': 'Solidity',
                'sources': {source_code_file: {'content': source_code}},
                'settings': {
                    "optimizer": {
                        "enabled": True,
                        "runs": 200
                    },
                    "evmVersion": evm_version,
                    "outputSelection": {
                        source_code_file: {
                            "*":
                                [
                                    "abi",
                                    "evm.deployedBytecode",
                                    "evm.bytecode.object",
                                    "evm.legacyAssembly",
                                ],
                        }
                    }
                }
            }, allow_paths='.')
        except Exception as e:
            print("Error: Solidity compilation failed!")
            print(e.message)
    return out

def get_interface_from_abi(abi):
    interface = {}
    for field in abi:
        if field['type'] == 'function':
            function_name = field['name']
            function_inputs = []
            signature = function_name + '('
            for i in range(len(field['inputs'])):
                input_type = field['inputs'][i]['type']
                function_inputs.append(input_type)
                signature += input_type
                if i < len(field['inputs']) - 1:
                    signature += ','
            signature += ')'
            hash = Web3.sha3(text=signature)[0:4].hex()
            interface[hash] = function_inputs
        elif field['type'] == 'constructor':
            function_inputs = []
            for i in range(len(field['inputs'])):
                input_type = field['inputs'][i]['type']
                function_inputs.append(input_type)
            interface['constructor'] = function_inputs
    if not "fallback" in interface:
        interface["fallback"] = []
    return interface

def get_function_signature_mapping(abi):
    mapping = {}
    for field in abi:
        if field['type'] == 'function':
            function_name = field['name']
            function_inputs = []
            signature = function_name + '('
            for i in range(len(field['inputs'])):
                input_type = field['inputs'][i]['type']
                signature += input_type
                if i < len(field['inputs']) - 1:
                    signature += ','
            signature += ')'
            hash = Web3.sha3(text=signature)[0:4].hex()
            mapping[hash] = signature
    if not "fallback" in mapping:
        mapping["fallback"] = "fallback"
    return mapping

def remove_swarm_hash(bytecode):
    if isinstance(bytecode, str):
        bytecode = re.sub(r"a165627a7a72305820\S{64}0029$", "", bytecode)
    return bytecode

def get_pcs_and_jumpis(bytecode):
    bytecode = bytes.fromhex(remove_swarm_hash(bytecode).replace("0x", ""))
    i = 0
    pcs = []
    jumpis = []
    while i < len(bytecode):
        opcode = bytecode[i]
        pcs.append(i)
        if opcode == 87: # JUMPI
            jumpis.append(hex(i))
        if opcode >= 96 and opcode <= 127: # PUSH
            size = opcode - 96 + 1
            i += size
        i += 1
    if len(pcs) == 0:
        pcs = [0]
    return (pcs, jumpis)

def convert_stack_value_to_int(stack_value):
    if stack_value[0] == int:
        return stack_value[1]
    elif stack_value[0] == bytes:
        return int.from_bytes(stack_value[1], "big")
    else:
        raise Exception("Error: Cannot convert stack value to int. Unknown type: " + str(stack_value[0]))

def convert_stack_value_to_hex(stack_value):
    if stack_value[0] == int:
        return hex(stack_value[1]).replace("0x", "").zfill(64)
    elif stack_value[0] == bytes:
        return stack_value[1].hex().zfill(64)
    else:
        raise Exception("Error: Cannot convert stack value to hex. Unknown type: " + str(stack_value[0]))

def is_fixed(value):
    return isinstance(value, int)

def split_len(seq, length):
    return [seq[i:i + length] for i in range(0, len(seq), length)]

def print_individual_solution_as_transaction(logger, individual_solution, color="", function_signature_mapping={}):
    for index, input in enumerate(individual_solution):
        transaction = input["transaction"]
        if not transaction["to"] == None:
            if transaction["data"].startswith("0x"):
                hash = transaction["data"][0:10]
            else:
                hash = transaction["data"][0:8]
            if len(individual_solution) == 1:
                if hash in function_signature_mapping:
                    logger.title(color+"Transaction - " + function_signature_mapping[hash] + ":")
                else:
                    logger.title(color+"Transaction:")
            else:
                if hash in function_signature_mapping:
                    logger.title(color+"Transaction " + str(index + 1) + " - " + function_signature_mapping[hash] + ":")
                else:
                    logger.title(color+"Transaction " + str(index + 1) + ":")
            logger.title(color+"-----------------------------------------------------")
            logger.title(color+"From:      " + transaction["from"])
            logger.title(color+"To:        " + str(transaction["to"]))
            logger.title(color+"Value:     " + str(transaction["value"]) + " Wei")
            logger.title(color+"Gas Limit: " + str(transaction["gaslimit"]))
            i = 0
            for data in split_len("0x" + transaction["data"].replace("0x", ""), 42):
                if i == 0:
                    logger.title(color+"Input:     " + str(data))
                else:
                    logger.title(color+"           " + str(data))
                i += 1
            logger.title(color+"-----------------------------------------------------")

def normalize_32_byte_hex_address(value):
    as_bytes = eth_utils.to_bytes(hexstr=value)
    return eth_utils.to_normalized_address(as_bytes[-20:])
