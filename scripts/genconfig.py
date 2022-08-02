#!/usr/bin/env python3

import os
import re
import sys

comment = re.compile(r'^\s*#')
assign = re.compile(r'^\s*([a-zA-Z0-9_]+)\s*(\?)?=\s*([^#]*)')

args = os.environ.copy()
for arg in sys.argv:
    if m := assign.match(arg):
        var = m[1].strip()
        val = m[3].strip()
        args[var] = val

defs = {}
try:
    with open("mk/config.mk") as f:
        for line in f:
            line = line.strip()
            if not comment.match(line):
                if m := assign.match(line):
                    var = m[1].strip()
                    default = m[3].strip()
                    val = default
                    if var in args:
                        val = args[var]
                    if default.lower() in ['y', 'n']:
                        defs["SPDK_{0}".format(var)] = 1 if val.lower() == 'y' else 0
                    else:
                        strval = val.replace('"', '\"')
                        defs["SPDK_{0}".format(var)] = strval
except IOError:
    print("mk/config.mk not found")

for key, value in sorted(defs.items()):
    if value == 0:
        print("#undef {0}".format(key))
    else:
        print("#define {0} {1}".format(key, value))
