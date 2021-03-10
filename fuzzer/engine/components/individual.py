#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import random

from copy import deepcopy, copy
from eth_abi import encode_abi
from eth_abi.exceptions import EncodingTypeError, ValueOutOfBounds, ParseError

from utils.utils import initialize_logger

class Individual():
    def __init__(self, generator):
        self.logger = initialize_logger("Individual")
        self.chromosome = []
        self.solution = []
        self.generator = generator

    @property
    def hash(self):
        if not self.solution:
            self.solution = self.decode()
        return str(hash(str([tx for tx in self.solution])))

    def init(self, chromosome=None):
        if not chromosome:
            self.chromosome = self.generator.generate_random_individual()
        else:
            self.chromosome = chromosome
        self.solution = self.decode()
        return self

    def clone(self):
        indv = self.__class__(generator=self.generator)
        indv.init(chromosome=deepcopy(self.chromosome))
        return indv

    def decode(self):
        solution = []
        for i in range(len(self.chromosome)):
            transaction = {}
            transaction["from"] = copy(self.chromosome[i]["account"])
            transaction["to"] = copy(self.chromosome[i]["contract"])
            transaction["value"] = copy(self.chromosome[i]["amount"])
            transaction["gaslimit"] = copy(self.chromosome[i]["gaslimit"])
            transaction["data"] = self.get_transaction_data_from_chromosome(i)

            block = {}
            if "timestamp" in self.chromosome[i] and self.chromosome[i]["timestamp"] is not None:
                block["timestamp"] = copy(self.chromosome[i]["timestamp"])
            if "blocknumber" in self.chromosome[i] and self.chromosome[i]["blocknumber"] is not None:
                block["blocknumber"] = copy(self.chromosome[i]["blocknumber"])

            global_state = {}
            if "balance" in self.chromosome[i] and self.chromosome[i]["balance"] is not None:
                global_state["balance"] = copy(self.chromosome[i]["balance"])
            if "call_return" in self.chromosome[i] and self.chromosome[i]["call_return"] is not None\
                    and len(self.chromosome[i]["call_return"]) > 0:
                global_state["call_return"] = copy(self.chromosome[i]["call_return"])
            if "extcodesize" in self.chromosome[i] and self.chromosome[i]["extcodesize"] is not None\
                    and len(self.chromosome[i]["extcodesize"]) > 0:
                global_state["extcodesize"] = copy(self.chromosome[i]["extcodesize"])

            environment = {}
            if "returndatasize" in self.chromosome[i] and self.chromosome[i]["returndatasize"] is not None:
                environment["returndatasize"] = copy(self.chromosome[i]["returndatasize"])

            input = {"transaction":transaction, "block" : block, "global_state" : global_state, "environment": environment}
            solution.append(input)
        return solution

    def get_transaction_data_from_chromosome(self, chromosome_index):
        data = ""
        arguments = []
        function = None
        for j in range(len(self.chromosome[chromosome_index]["arguments"])):
            if self.chromosome[chromosome_index]["arguments"][j] == "fallback":
                function = "fallback"
                data += random.choice(["", "00000000"])
            elif self.chromosome[chromosome_index]["arguments"][j] == "constructor":
                function = "constructor"
                data += self.generator.bytecode
            elif not type(self.chromosome[chromosome_index]["arguments"][j]) is bytearray and \
                    not type(self.chromosome[chromosome_index]["arguments"][j]) is list and \
                    self.chromosome[chromosome_index]["arguments"][j] in self.generator.interface:
                function = self.chromosome[chromosome_index]["arguments"][j]
                data += self.chromosome[chromosome_index]["arguments"][j]
            else:
                arguments.append(self.chromosome[chromosome_index]["arguments"][j])
        try:
            argument_types = [argument_type.replace(" storage", "").replace(" memory", "") for argument_type in self.generator.interface[function]]
            data += encode_abi(argument_types, arguments).hex()
        except Exception as e:
            self.logger.error("%s", e)
            self.logger.error("%s: %s -> %s", function, self.generator.interface[function], arguments)
            sys.exit(-6)
        return data
