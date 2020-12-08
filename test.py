#!/usr/bin/env python

import os
import sys
import pathlib
import importlib.util

if sys.platform.startswith('win'):
    libpcap_dir = pathlib.Path(importlib.util.find_spec('libpcap').origin).parent
    dll_path = libpcap_dir / '_platform' / '_windows' / ('x64' if sys.maxsize.bit_length() > 32 else 'x86') / 'wpcap'
    os.environ['PATH'] += os.pathsep + str(dll_path)

import libpcap
