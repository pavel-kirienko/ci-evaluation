#!/usr/bin/env python

import os
import sys
import pathlib
import importlib.util

if sys.platform.startswith('win'):
    spec = importlib.util.find_spec('libpcap')
    if spec:
        is_64_bit = sys.maxsize.bit_length() > 32
        libpcap_dir = pathlib.Path(spec.origin).parent
        dll_path = libpcap_dir / '_platform' / '_windows' / ('x64' if is_64_bit else 'x86') / 'wpcap'
        os.environ['PATH'] += os.pathsep + str(dll_path)

import libpcap
