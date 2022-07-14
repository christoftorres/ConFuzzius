#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from z3 import is_expr
from z3.z3util import get_vars

class ArbitraryMemoryAccessDetector():
    def __init__(self):
        self.init()

    def init(self):
        self.swc_id = 124
        self.severity = "High"

    def detect_arbitrary_memory_access(self, tainted_record, individual, current_instruction, transaction_index):
        if current_instruction["op"] == "SSTORE":
            if tainted_record and tainted_record.stack:
                tainted_index = tainted_record.stack[-1]
                tainted_value = tainted_record.stack[-2]
                if tainted_index and tainted_value and is_expr(tainted_index[0]) and is_expr(tainted_value[0]):
                    if get_vars(tainted_index[0]) and get_vars(tainted_value[0]):
                        tainted_index_var = get_vars(tainted_index[0])[0]
                        tainted_value_var = get_vars(tainted_value[0])[0]
                        if tainted_index != tainted_value and "calldataload_" in str(tainted_index[0]) and "calldataload_" in str(tainted_value[0]):
                            if len(str(tainted_index_var).split("_")) == 3:
                                transaction_index = int(str(tainted_index_var).split("_")[1])
                                argument_index = int(str(tainted_index_var).split("_")[2]) + 1
                                if type(individual.chromosome[transaction_index]["arguments"][argument_index]) is int and individual.chromosome[transaction_index]["arguments"][argument_index] > 2**128-1:
                                    return current_instruction["pc"], transaction_index
        return None, None
