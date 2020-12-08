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


def _filter_devices(address_families: typing.Sequence[AddressFamily]) -> typing.List[str]:
    """
    Returns a list of local network devices that have at least one address from the specified list of address
    families. This is needed so that we won't attempt capturing Ethernet frames on a CAN device, for instance.
    Such filtering automatically excludes devices whose interfaces are down, since they don't have any address.
    """
    import libpcap as pcap
    err_buf = ctypes.create_string_buffer(pcap.PCAP_ERRBUF_SIZE)
    devices = ctypes.POINTER(pcap.pcap_if_t)()
    if pcap.findalldevs(ctypes.byref(devices), err_buf) != 0:
        raise TransportError(f"Could not list network devices: {err_buf.value.decode()}")
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
        if name == 'any':
            _logger.debug('Synthetic device %r does not support promiscuous mode, skipping', name)
        else:
            a = d.addresses
            while a:
                a = a.contents
                if a.addr and a.addr.contents.sa_family in address_families:
                    dev_names.append(name)
                    break
                a = a.next
            else:
                _logger.debug('Device %r is incompatible with requested address families %s, skipping',
                              name, address_families)
        d = d.next
    pcap.freealldevs(devices)
    return dev_names


print(_filter_devices([AddressFamily.AF_INET]))
