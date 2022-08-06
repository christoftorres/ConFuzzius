#!/usr/bin/env python3
# -*- coding: utf-8 -*-

class AssertionFailureDetector():
    def __init__(self):
        self.init()

    def init(self):
        self.swc_id = 110
        self.severity = "Medium"

    def detect_assertion_failure(self, current_instruction, transaction_index):
        if current_instruction["op"] in ["ASSERTFAIL", "INVALID"]:
            return current_instruction["pc"], transaction_index
        return None, None
