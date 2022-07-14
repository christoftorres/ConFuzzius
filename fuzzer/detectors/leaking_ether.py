#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from z3 import is_expr
from utils import settings
from utils.utils import convert_stack_value_to_int, convert_stack_value_to_hex

class LeakingEtherDetector():
    def __init__(self):
        self.init()

    def init(self):
        self.swc_id = 105
        self.severity = "High"
        self.leaks = {}
        self.spenders = set()

    def detect_leaking_ether(self, current_instruction, taint_record, individual, transaction_index, previous_branch):
        if current_instruction["op"] == "STOP":
            if individual.solution[transaction_index]["transaction"]["value"] > 0:
                self.spenders.add(individual.solution[transaction_index]["transaction"]["from"])
            if transaction_index in self.leaks:
                if individual.solution[transaction_index]["transaction"]["from"] not in self.spenders:
                    return self.leaks[transaction_index]
        elif current_instruction["op"] == "CALL":
            to = "0x"+convert_stack_value_to_hex(current_instruction["stack"][-2]).lstrip("0")
            # Check if the destination of the call is an attacker
            if to in settings.ATTACKER_ACCOUNTS and to == individual.solution[transaction_index]["transaction"]["from"]:
                # Check if the value of the call is larger than zero or the contract balance
                if convert_stack_value_to_int(current_instruction["stack"][-3]) > 0 or taint_record and taint_record.stack[-3] and is_expr(taint_record.stack[-3][0]) and "balance" in str(taint_record.stack[-3][0]):
                    # Check if the destination did not spend ether
                    if not to in self.spenders:
                        # Check if the destination was not previously passed as argument by a trusted user
                        address_passed_as_argument = False
                        for i in range(transaction_index):
                            for argument in individual.chromosome[i]["arguments"]:
                                if argument in settings.ATTACKER_ACCOUNTS and individual.solution[i]["transaction"]["from"] not in settings.ATTACKER_ACCOUNTS:
                                    address_passed_as_argument = True
                        if not address_passed_as_argument:
                            self.leaks[transaction_index] = current_instruction["pc"], transaction_index
        return None, None
