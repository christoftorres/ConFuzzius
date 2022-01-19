#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from z3.z3util import get_vars
from utils.utils import convert_stack_value_to_int

class IntegerOverflowDetector():
    def __init__(self):
        self.init()

    def init(self):
        self.swc_id = 101
        self.severity = "High"
        self.overflows = {}
        self.underflows = {}

    def detect_integer_overflow(self, previous_instruction, current_instruction, tainted_record):
        if previous_instruction and previous_instruction["op"] == "ADD":
            a = convert_stack_value_to_int(previous_instruction["stack"][-2])
            b = convert_stack_value_to_int(previous_instruction["stack"][-1])
            c = convert_stack_value_to_int(current_instruction["stack"][-1])
            if a + b != c:
                if tainted_record and tainted_record.stack and tainted_record.stack[-1]:
                    if get_vars(tainted_record.stack[-1][0]):
                        self.overflows[previous_instruction["pc"]] = get_vars(tainted_record.stack[-1][0])

        elif previous_instruction and previous_instruction["op"] == "MUL":
            a = convert_stack_value_to_int(previous_instruction["stack"][-2])
            b = convert_stack_value_to_int(previous_instruction["stack"][-1])
            c = convert_stack_value_to_int(current_instruction["stack"][-1])
            if a * b != c:
                if tainted_record and tainted_record.stack and tainted_record.stack[-1]:
                    if get_vars(tainted_record.stack[-1][0]):
                        self.overflows[previous_instruction["pc"]] = get_vars(tainted_record.stack[-1][0])

        elif previous_instruction and previous_instruction["op"] == "SUB":
            a = convert_stack_value_to_int(previous_instruction["stack"][-2])
            b = convert_stack_value_to_int(previous_instruction["stack"][-1])
            c = convert_stack_value_to_int(current_instruction["stack"][-1])
            if a - b != c:
                if tainted_record and tainted_record.stack and tainted_record.stack[-1]:
                    if get_vars(tainted_record.stack[-1][0]):
                        self.underflows[previous_instruction["pc"]] = get_vars(tainted_record.stack[-1][0])

        if current_instruction and current_instruction["op"] == "SSTORE":
            if tainted_record and tainted_record.stack and tainted_record.stack[-2]:
                for pc in self.overflows:
                    for var1 in get_vars(tainted_record.stack[-2][0]):
                        for var2 in self.overflows[pc]:
                            if var1 == var2:
                                return pc, "overflow"
                for pc in self.underflows:
                    for var1 in get_vars(tainted_record.stack[-2][0]):
                        for var2 in self.underflows[pc]:
                            if var1 == var2:
                                return pc, "underflow"
        return None, None
