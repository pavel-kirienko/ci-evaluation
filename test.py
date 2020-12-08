#!/usr/bin/env python

import os
import sys
import pathlib
import importlib.util

dll_path = pathlib.Path(importlib.util.find_spec('libpcap').origin).parent / '_platform' / '_windows' / ('x64' if sys.maxsize.bit_length() > 32 else 'x86') / 'wpcap'
print('dll_path', dll_path)
os.environ['PATH'] += os.pathsep + str(dll_path)

import libpcap


