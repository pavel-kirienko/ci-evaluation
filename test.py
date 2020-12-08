#!/usr/bin/env python

import os
import sys
import pathlib
import importlib

dll_path = pathlib.Path(importlib.util.find_spec('libpcap').origin).parent / '_platform' / '_windows' / ('x64' if sys.maxsize.bit_length() > 32 else 'x86')
print('dll_path', dll_path)
os.environ['PATH'] += os.pathsep + dll_path

import libpcap


