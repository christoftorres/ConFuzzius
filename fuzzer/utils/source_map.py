#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from utils.utils import get_pcs_and_jumpis

class Source:
    def __init__(self, filename):
        self.filename = filename
        self.content = self._load_content()
        self.line_break_positions = self._load_line_break_positions()

    def _load_content(self):
        with open(self.filename, 'r') as f:
            content = f.read()
        return content

    def _load_line_break_positions(self):
        return [i for i, letter in enumerate(self.content) if letter == '\n']

class SourceMap:
    position_groups = {}
    sources = {}
    compiler_output = None

    def __init__(self, cname, compiler_output):
        self.cname = cname
        SourceMap.compiler_output = compiler_output
        SourceMap.position_groups = SourceMap._load_position_groups_standard_json()
        self.source = self._get_source()
        self.positions = self._get_positions()
        self.instr_positions = self._get_instr_positions()

    def get_source_code(self, pc):
        try:
            pos = self.instr_positions[pc]
        except:
            return ""
        begin = pos['begin']
        end = pos['end']
        return self.source.content[begin:end]

    def get_buggy_line(self, pc):
        #print(self.instr_positions)
        try:
            pos = self.instr_positions[pc]
        except:
            return ""
        #location = self.get_location(pc)
        #print(location)
        try:
            #begin = self.source.line_break_positions[location['begin']['line'] - 1] + 1
            begin = pos['begin']
            end = pos['end']
            #print(begin)
            #print(end)
            #print(self.source.content[begin:end])
            return self.source.content[begin:end]
        except:
            return ""

    def get_location(self, pc):
        pos = self.instr_positions[pc]
        return self._convert_offset_to_line_column(pos)

    def _get_source(self):
        fname = self.get_filename()
        if fname not in SourceMap.sources:
            SourceMap.sources[fname] = Source(fname)
        return SourceMap.sources[fname]

    @classmethod
    def _load_position_groups_standard_json(cls):
        return cls.compiler_output["contracts"]

    def _get_positions(self):
        filename, contract_name = self.cname.split(":")
        asm = SourceMap.position_groups[filename][contract_name]['evm']['legacyAssembly']['.data']['0']
        positions = asm['.code']
        while(True):
            try:
                positions.append(None)
                positions += asm['.data']['0']['.code']
                asm = asm['.data']['0']
            except:
                break
        return positions

    def _get_instr_positions(self):
        j = 0
        instr_positions = {}
        try:
            filename, contract_name = self.cname.split(":")
            bytecode = self.compiler_output['contracts'][filename][contract_name]["evm"]["deployedBytecode"]["object"]
            pcs = get_pcs_and_jumpis(bytecode)[0]
            for i in range(len(self.positions)):
                if self.positions[i] and self.positions[i]['name'] != 'tag':
                    instr_positions[pcs[j]] = self.positions[i]
                    j += 1
            return instr_positions
        except:
            return instr_positions

    def _convert_offset_to_line_column(self, pos):
        ret = {}
        ret['begin'] = None
        ret['end'] = None
        if pos['begin'] >= 0 and (pos['end'] - pos['begin'] + 1) >= 0:
            ret['begin'] = self._convert_from_char_pos(pos['begin'])
            ret['end'] = self._convert_from_char_pos(pos['end'])
        return ret

    def _convert_from_char_pos(self, pos):
        line = self._find_lower_bound(pos, self.source.line_break_positions)
        col = 0
        if line in self.source.line_break_positions:
            if self.source.line_break_positions[line] != pos:
                line += 1
            begin_col = 0 if line == 0 else self.source.line_break_positions[line - 1] + 1
            col = pos - begin_col
        else:
            line += 1
        return {'line': line, 'column': col}

    def _find_lower_bound(self, target, array):
        start = 0
        length = len(array)
        while length > 0:
            half = length >> 1
            middle = start + half
            if array[middle] <= target:
                length = length - 1 - half
                start = middle + 1
            else:
                length = half
        return start - 1

    def get_filename(self):
        return self.cname.split(":")[0]
