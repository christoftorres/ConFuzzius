#!/usr/bin/env python3
# -*- coding: utf-8 -*-

''' Mutation implementation. '''

import random

from utils import settings
from ...plugin_interfaces.operators.mutation import Mutation

class Mutation(Mutation):
    def __init__(self, pm):
        '''
        :param pm: The probability of mutation (usually between 0.001 ~ 0.1)
        :type pm: float in (0.0, 1.0]
        '''
        if pm <= 0.0 or pm > 1.0:
            raise ValueError('Invalid mutation probability')

        self.pm = pm

    def mutate(self, individual, engine):
        for gene in individual.chromosome:
            # TRANSACTION
            function_hash = gene["arguments"][0]
            for element in gene:
                if element == "account" and random.random() <= self.pm:
                    gene["account"] = individual.generator.get_random_account(function_hash)
                elif element == "amount" and random.random() <= self.pm:
                    gene["amount"] = individual.generator.get_random_amount(function_hash)
                elif element == "gaslimit" and random.random() <= self.pm:
                    gene["gaslimit"] = individual.generator.get_random_gaslimit(function_hash)
                else:
                    for argument_index in range(1, len(gene["arguments"])):
                        if random.random() > self.pm:
                            continue
                        argument_type = individual.generator.interface[function_hash][argument_index - 1]
                        argument = individual.generator.get_random_argument(argument_type,
                                                                            function_hash,
                                                                            argument_index - 1)
                        gene["arguments"][argument_index] = argument

            # BLOCK
            if "timestamp" in gene:
                if random.random() <= self.pm:
                    gene["timestamp"] = individual.generator.get_random_timestamp(function_hash)
            else:
                gene["timestamp"] = individual.generator.get_random_timestamp(function_hash)

            if "blocknumber" in gene:
                if random.random() <= self.pm:
                    gene["blocknumber"] = individual.generator.get_random_blocknumber(function_hash)
            else:
                gene["blocknumber"] = individual.generator.get_random_blocknumber(function_hash)

            # GLOBAL STATE
            if "balance" in gene:
                if random.random() <= self.pm:
                    gene["balance"] = individual.generator.get_random_balance(function_hash)
            else:
                gene["balance"] = individual.generator.get_random_balance(function_hash)

            if "call_return" in gene:
                for address in gene["call_return"]:
                    if random.random() <= self.pm:
                        gene["call_return"][address] = individual.generator.get_random_callresult(function_hash, address)
            else:
                gene["call_return"] = dict()
                address, call_return_value = individual.generator.get_random_callresult_and_address(function_hash)
                if address and address not in gene["call_return"]:
                    gene["call_return"][address] = call_return_value

            if "extcodesize" in gene:
                for address in gene["extcodesize"]:
                    if random.random() <= self.pm:
                        gene["extcodesize"][address] = individual.generator.get_random_extcodesize(function_hash, address)
            else:
                gene["extcodesize"] = dict()
                address, extcodesize_value = individual.generator.get_random_extcodesize_and_address(function_hash)
                if address and address not in gene["extcodesize"]:
                    gene["extcodesize"][address] = extcodesize_value

            if "returndatasize" in gene:
                for address in gene["returndatasize"]:
                    if random.random() <= self.pm:
                        gene["returndatasize"][address] = individual.generator.get_random_returndatasize(function_hash, address)
            else:
                gene["returndatasize"] = dict()
                address, returndatasize_value = individual.generator.get_random_returndatasize_and_address(function_hash)
                if address and address not in gene["returndatasize"]:
                    gene["returndatasize"][address] = returndatasize_value

        individual.solution = individual.decode()
        return individual
