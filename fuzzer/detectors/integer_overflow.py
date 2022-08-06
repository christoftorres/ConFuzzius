#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from z3 import BitVec
from utils.utils import convert_stack_value_to_int, convert_stack_value_to_hex

class IntegerOverflowDetector():
    def __init__(self):
        self.init()

    def init(self):
        self.swc_id = 101
        self.severity = "High"
        self.overflows = {}
        self.underflows = {}
        self.compiler_value_negation = False

    def detect_integer_overflow(self, mfe, tainted_record, previous_instruction, current_instruction, individual, transaction_index):
        if previous_instruction and previous_instruction["op"] == "NOT" and current_instruction and current_instruction["op"] == "ADD":
            self.compiler_value_negation = True
        # Addition
        elif previous_instruction and previous_instruction["op"] == "ADD":
            a = convert_stack_value_to_int(previous_instruction["stack"][-2])
            b = convert_stack_value_to_int(previous_instruction["stack"][-1])
            if a + b != convert_stack_value_to_int(current_instruction["stack"][-1]) and not self.compiler_value_negation:
                if tainted_record and tainted_record.stack and tainted_record.stack[-1]:
                    index = ''.join(str(taint) for taint in tainted_record.stack[-1])
                    if "calldataload" in index or "callvalue" in index:
                        _function_hash = individual.chromosome[transaction_index]["arguments"][0]
                        _is_string = False
                        for _argument_index in [int(a.split("_")[-1]) for a in index.split() if a.startswith("calldataload_"+str(transaction_index)+"_")]:
                            if individual.generator.interface[_function_hash][_argument_index] == "string":
                                _is_string = True
                        if not _is_string:
                            self.overflows[index] = previous_instruction["pc"], transaction_index
        # Multiplication
        elif previous_instruction and previous_instruction["op"] == "MUL":
            a = convert_stack_value_to_int(previous_instruction["stack"][-2])
            b = convert_stack_value_to_int(previous_instruction["stack"][-1])
            if a * b != convert_stack_value_to_int(current_instruction["stack"][-1]):
                if tainted_record and tainted_record.stack and tainted_record.stack[-1]:
                    index = ''.join(str(taint) for taint in tainted_record.stack[-1])
                    if "calldataload" in index or "callvalue" in index:
                        self.overflows[index] = previous_instruction["pc"], transaction_index
        # Subtraction
        elif previous_instruction and previous_instruction["op"] == "SUB":
            a = convert_stack_value_to_int(previous_instruction["stack"][-1])
            b = convert_stack_value_to_int(previous_instruction["stack"][-2])
            if a - b != convert_stack_value_to_int(current_instruction["stack"][-1]):
                if tainted_record and tainted_record.stack and tainted_record.stack[-1]:
                    index = ''.join(str(taint) for taint in tainted_record.stack[-1])
                    self.underflows[index] = previous_instruction["pc"], transaction_index
                else:
                    tainted_record = mfe.symbolic_taint_analyzer.get_tainted_record(index=-1)
                    if tainted_record:
                        tainted_record.stack[-2] = [BitVec("_".join(["underflow", hex(previous_instruction["pc"])]), 256)]
                        index = ''.join(str(taint) for taint in tainted_record.stack[-2])
                        self.underflows[index] = previous_instruction["pc"], transaction_index
        # Check if overflow flows into storage
        if current_instruction and current_instruction["op"] == "SSTORE":
            if tainted_record and tainted_record.stack and tainted_record.stack[-2]: # Storage value
                index = ''.join(str(taint) for taint in tainted_record.stack[-2])
                if index in self.overflows:
                    return self.overflows[index][0], self.overflows[index][1], "overflow"
                if index in self.underflows:
                    return self.underflows[index][0], self.underflows[index][1], "underflow"
        # Check if overflow flows into call
        elif current_instruction and current_instruction["op"] == "CALL":
            if tainted_record and tainted_record.stack and tainted_record.stack[-3]: # Call value
                index = ''.join(str(taint) for taint in tainted_record.stack[-3])
                if index in self.overflows:
                    return self.overflows[index][0], self.overflows[index][1], "overflow"
                if index in self.underflows:
                    return self.underflows[index][0], self.underflows[index][1], "underflow"
        # Check if overflow flows into condition
        elif current_instruction and current_instruction["op"] in ["LT", "GT", "SLT", "SGT", "EQ"]:
            if tainted_record and tainted_record.stack:
                if tainted_record.stack[-1]: # First operand
                    index = ''.join(str(taint) for taint in tainted_record.stack[-1])
                    if index in self.overflows:
                        return self.overflows[index][0], self.overflows[index][1], "overflow"
                    if index in self.underflows:
                        return self.underflows[index][0], self.underflows[index][1], "underflow"
                if tainted_record.stack[-2]: # Second operand
                    index = ''.join(str(taint) for taint in tainted_record.stack[-2])
                    if index in self.overflows:
                        return self.overflows[index][0], self.overflows[index][1], "overflow"
                    if index in self.underflows:
                        return self.underflows[index][0], self.underflows[index][1], "underflow"
        return None, None, None
