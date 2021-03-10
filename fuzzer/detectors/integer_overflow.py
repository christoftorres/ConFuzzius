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
            #print(convert_stack_value_to_int(previous_instruction["stack"][-2]))
            #print(convert_stack_value_to_int(previous_instruction["stack"][-1]))
            if a + b != convert_stack_value_to_int(current_instruction["stack"][-1]) and not self.compiler_value_negation:
                #print("!!!!!!!!")
                #print("!!!!!!!!")
                #print("addition overflow")
                #print("!!!!!!!!")
                #print("!!!!!!!!")
                if tainted_record and tainted_record.stack and tainted_record.stack[-1]:
                    index = ''.join(str(taint) for taint in tainted_record.stack[-1])
                    if "calldataload" in index or "callvalue" in index:
                        _function_hash = individual.chromosome[transaction_index]["arguments"][0]
                        _is_string = False
                        for _argument_index in [int(a.split("_")[-1]) for a in index.split() if a.startswith("calldataload_"+str(transaction_index)+"_")]:
                            if individual.generator.interface[_function_hash][_argument_index] == "string":
                                _is_string = True
                        if not _is_string:
                            self.overflows[index] = previous_instruction["pc"]

        # Multiplication
        elif previous_instruction and previous_instruction["op"] == "MUL":
            a = convert_stack_value_to_int(previous_instruction["stack"][-2])
            b = convert_stack_value_to_int(previous_instruction["stack"][-1])
            if a * b != convert_stack_value_to_int(current_instruction["stack"][-1]):
                """print(convert_stack_value_to_int(previous_instruction["stack"][-2]))
                print(convert_stack_value_to_int(previous_instruction["stack"][-1]))
                print(convert_stack_value_to_hex(previous_instruction["stack"][-1]))
                print(convert_stack_value_to_int(current_instruction["stack"][-1]))
                print(convert_stack_value_to_hex(current_instruction["stack"][-1]))
                print(" ")"""
                #print("Multiplication overflow")
                if tainted_record and tainted_record.stack and tainted_record.stack[-1]:
                    index = ''.join(str(taint) for taint in tainted_record.stack[-1])
                    #print("yes")
                    if "calldataload" in index or "callvalue" in index:
                        #print("added")
                        self.overflows[index] = previous_instruction["pc"]
                        #tainted_record.stack[-2] = [BitVec("_".join(["overflow", hex(previous_instruction["pc"])]), 256)]
                        #index = ''.join(str(taint) for taint in tainted_record.stack[-2])
                        #self.overflows[index] = previous_instruction["pc"]
                #else:
                #    print("nope")
                #print("")
        # Subtraction
        elif previous_instruction and previous_instruction["op"] == "SUB":
            a = convert_stack_value_to_int(previous_instruction["stack"][-1])
            b = convert_stack_value_to_int(previous_instruction["stack"][-2])
            if a - b != convert_stack_value_to_int(current_instruction["stack"][-1]):
                if tainted_record and tainted_record.stack and tainted_record.stack[-1]:
                    index = ''.join(str(taint) for taint in tainted_record.stack[-1])
                    self.underflows[index] = previous_instruction["pc"]
                else:
                    tainted_record = mfe.symbolic_taint_analyzer.get_tainted_record(index=-1)
                    if tainted_record:
                        tainted_record.stack[-2] = [BitVec("_".join(["underflow", hex(previous_instruction["pc"])]), 256)]
                        index = ''.join(str(taint) for taint in tainted_record.stack[-2])
                        self.underflows[index] = previous_instruction["pc"]

        # Check if overflow flows into storage
        if current_instruction and current_instruction["op"] == "SSTORE":
            #print("sstore")
            if tainted_record and tainted_record.stack and tainted_record.stack[-2]: # Storage value
                index = ''.join(str(taint) for taint in tainted_record.stack[-2])
                #print("sstore index")
                #print(index)

                if index in self.overflows:
                    return self.overflows[index], "overflow"
                if index in self.underflows:
                    return self.underflows[index], "underflow"
        # Check if overflow flows into call
        elif current_instruction and current_instruction["op"] == "CALL":
            if tainted_record and tainted_record.stack and tainted_record.stack[-3]: # Call value
                #print(tainted_record.stack)
                index = ''.join(str(taint) for taint in tainted_record.stack[-3])
                if index in self.overflows:
                    #print("!!!!!!!")
                    #print("!!!!!!!")
                    #print("yolo")
                    #print("!!!!!!!")
                    #print("!!!!!!!")
                    return self.overflows[index], "overflow"
                if index in self.underflows:
                    return self.underflows[index], "underflow"
        # Check if overflow flows into condition
        elif current_instruction and current_instruction["op"] in ["LT", "GT", "SLT", "SGT", "EQ"]:
            #print(tainted_record.stack)
            if tainted_record and tainted_record.stack:
                if tainted_record.stack[-1]: # First operand
                    index = ''.join(str(taint) for taint in tainted_record.stack[-1])
                    if index in self.overflows:
                        return self.overflows[index], "overflow"
                    if index in self.underflows:
                        return self.underflows[index], "underflow"
                if tainted_record.stack[-2]: # Second operand
                    index = ''.join(str(taint) for taint in tainted_record.stack[-2])
                    if index in self.overflows:
                        return self.overflows[index], "overflow"
                    if index in self.underflows:
                        return self.underflows[index], "underflow"
        return None, None
