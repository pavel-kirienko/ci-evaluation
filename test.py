#!/usr/bin/env python

import os
import sys
import pathlib
import importlib.util
import time
import typing
import ctypes
import socket
from socket import AddressFamily
import logging
import threading
import dataclasses


_logger = logging.getLogger(__name__)


if sys.platform.startswith('win'):
    spec = importlib.util.find_spec('libpcap')
    if spec:
        is_64_bit = sys.maxsize.bit_length() > 32
        libpcap_dir = pathlib.Path(spec.origin).parent
        dll_path = libpcap_dir / '_platform' / '_windows' / ('x64' if is_64_bit else 'x86') / 'wpcap'
        os.environ['PATH'] += os.pathsep + str(dll_path)


def _find_devices() -> typing.List[str]:
    """
    Returns a list of local network devices that can be captured from.
    Raises a PermissionError if the user is suspected to lack the privileges necessary for capture.

    We used to filter the devices by address family, but it turned out to be a dysfunctional solution because
    a device does not necessarily have to have an address in a particular family to be able to capture packets
    of that kind. For instance, on Windows, a virtual network adapter may have no addresses while still being
    able to capture packets.
    """
    import libpcap as pcap
    err_buf = ctypes.create_string_buffer(pcap.PCAP_ERRBUF_SIZE)
    devices = ctypes.POINTER(pcap.pcap_if_t)()
    if pcap.findalldevs(ctypes.byref(devices), err_buf) != 0:
        raise Exception(f"Could not list network devices: {err_buf.value.decode()}")
    if not devices:
        # This may seem odd, but libpcap returns an empty list if the user is not allowed to perform capture.
        # This is documented in the API docs as follows:
        #   Note that there may be network devices that cannot be opened by the process calling pcap_findalldevs(),
        #   because, for example, that process does not have sufficient privileges to open them for capturing;
        #   if so, those devices will not appear on the list.
        raise PermissionError("No capturable devices have been found. Do you have the required privileges?")
    dev_names: typing.List[str] = []
    d = typing.cast(ctypes.Structure, devices)
    while d:
        d = d.contents
        name = d.name.decode()
        if name != 'any':
            dev_names.append(name)
        else:
            _logger.debug('Synthetic device %r does not support promiscuous mode, skipping', name)
        d = d.next
    pcap.freealldevs(devices)
    return dev_names


print(_find_devices())
