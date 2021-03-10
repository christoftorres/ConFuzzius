#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from z3 import is_expr
from z3.z3util import get_vars
from utils.utils import convert_stack_value_to_int

class UnhandledExceptionDetector():
    def __init__(self):
        self.init()

    def init(self):
        self.swc_id = 104
        self.severity = "Medium"
        self.exceptions = {}

    def detect_unhandled_exception(self, previous_instruction, current_instruction, tainted_record):
        # Register all exceptions
        if previous_instruction and previous_instruction["op"] in ["CALL", "CALLCODE", "DELEGATECALL", "STATICCALL"] and convert_stack_value_to_int(current_instruction["stack"][-1]) == 1:
            if tainted_record and tainted_record.stack and tainted_record.stack[-1] and is_expr(tainted_record.stack[-1][0]):
                self.exceptions[tainted_record.stack[-1][0]] = previous_instruction["pc"]
        # Remove all handled exceptions
        elif current_instruction["op"] == "JUMPI" and self.exceptions:
            if tainted_record and tainted_record.stack and tainted_record.stack[-2] and is_expr(tainted_record.stack[-2][0]):
                for var in get_vars(tainted_record.stack[-2][0]):
                    if var in self.exceptions:
                        del self.exceptions[var]
        # Report all unhandled exceptions at termination
        elif current_instruction["op"] in ["RETURN", "STOP", "SUICIDE", "SELFDESTRUCT"] and self.exceptions:
            for exception in self.exceptions:
                return self.exceptions[exception]
        return None
