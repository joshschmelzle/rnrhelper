# -*- coding: utf-8 -*-
#
# rnrhelper : a RNR helper for 6 GHz only APs
# Copyright : (c) 2022 Josh Schmelzle
# License : BSD-3-Clause
# Maintainer : josh@joshschmelzle.com
#                  _          _
#  _ __ _ __  _ __| |__   ___| |_ __   ___ _ __
# | '__| '_ \| '__| '_ \ / _ \ | '_ \ / _ \ '__|
# | |  | | | | |  | | | |  __/ | |_) |  __/ |
# |_|  |_| |_|_|  |_| |_|\___|_| .__/ \___|_|
#                              |_|

"""
rnrhelper.helpers
~~~~~~~~~~~~~~~~~

helper functions for rnrhelper
"""

import argparse
import logging
import logging.config
import os
from argparse import ArgumentTypeError

from rnrhelper.__version__ import __version__
from rnrhelper.constants import CHANNELS


def setup_logger(args) -> None:  # type: ignore
    """Configure and set logging levels"""
    logging_level = logging.INFO

    if args.debug:
        logging_level = logging.DEBUG

    default_logging = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "standard": {"format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s"}
        },
        "handlers": {
            "default": {
                "level": logging_level,
                "formatter": "standard",
                "class": "logging.StreamHandler",
                "stream": "ext://sys.stdout",
            }
        },
        "loggers": {"": {"handlers": ["default"], "level": logging_level}},
    }
    logging.config.dictConfig(default_logging)


def channel(value: str) -> int:
    """Check if channel is valid"""
    ch = int(value)
    if any(ch in band for band in CHANNELS.values()):
        return ch
    raise ArgumentTypeError("%s is not a valid 6 GHz channel" % ch)


def ssid(ssid: str) -> str:
    """Check if SSID is valid"""
    if len(ssid) > 32:
        raise ArgumentTypeError("ssid length cannot be greater than 32")
    return ssid


def bssid(bssid: str) -> str:
    """Check if BSSID is valid format"""
    # removes separator from MAC address"""
    _mac = bssid.translate(str.maketrans("", "", ":-."))
    _hex = [
        "0",
        "1",
        "2",
        "3",
        "4",
        "5",
        "6",
        "7",
        "8",
        "9",
        "a",
        "b",
        "c",
        "d",
        "e",
        "f",
    ]
    _invalidchars = []
    for _char in _mac:
        if _char not in _hex:
            _invalidchars.append(_char)
    if _invalidchars:
        raise ArgumentTypeError("Invalid characters in BSSID format %s" % _invalidchars)
    if len(_mac) != 12:
        raise ArgumentTypeError(
            "BSSID must be exactly 12 characters trimmed but we found %s " % len(_mac)
        )
    return _mac


def interface(interface: str) -> str:
    discovered_interfaces = []
    for iface in os.listdir("/sys/class/net"):
        iface_path = os.path.join("/sys/class/net", iface)
        if os.path.isdir(iface_path):
            if "phy80211" in os.listdir(iface_path):
                discovered_interfaces.append(iface)
    if interface not in discovered_interfaces:
        raise ArgumentTypeError(
            "{} is not a valid phy80211 interface".format(interface)
        )
    return interface


def oc(oc: str) -> int:
    """Check if Operating Class is valid"""
    try:
        _oc = int(oc)
    except ValueError:
        raise ArgumentTypeError("%s is not an integer" % oc)
    if _oc not in [131, 132, 133, 134]:
        raise ArgumentTypeError(
            "%s is not a supported 6 GHz operating class. try 131, 132, 133, or 134"
            % _oc
        )
    return _oc


def setup_parser() -> argparse.ArgumentParser:
    """Set default values and handle arg parser"""
    description_line1 = "rnrhelper is a RNR helper for 6 GHz only APs."
    description_line2 = 'rnrhelper will create and broadcast a SSID (named "rnrhelper") on channel 1 (2412) by default.'
    description_blurb = "%(description_line1)s\r\n\r\n%(description_line2)s" % locals()
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=description_blurb,
    )

    parser._action_groups.pop()
    required = parser.add_argument_group("required arguments")
    required.add_argument(
        "-i",
        dest="interface",
        type=interface,
        metavar="<interface>",
        required=True,
        help="set network interface for rnrhelper to broadcast on",
    )
    required.add_argument(
        "-b",
        dest="bssid",
        type=bssid,
        metavar="<neighbor bssid>",
        required=True,
        help="set the RNR bssid",
    )
    required.add_argument(
        "-oc",
        dest="oc",
        type=oc,
        metavar="<neighbor operating class>",
        required=True,
        help="set the RNR operating class",
    )
    required.add_argument(
        "-c",
        dest="channel",
        type=channel,
        metavar="<neighbor channel>",
        required=True,
        help="set the RNR channel",
    )
    required.add_argument(
        "-s",
        dest="ssid",
        type=ssid,
        metavar="<neighbor ssid>",
        required=True,
        help="set the RNR SSID (required to generate 4 byte short SSID)",
    )

    optional = parser.add_argument_group("optional arguments")
    optional.add_argument(
        "--debug",
        dest="debug",
        action="store_true",
        default=False,
        help="increase logging output",
    )
    parser.add_argument(
        "--nostage",
        dest="no_interface_prep",
        action="store_true",
        default=False,
        help="disable interface staging (default: %(default)s)",
    )
    optional.add_argument(
        "--no_bpf_filters",
        dest="no_bpf_filters",
        action="store_true",
        default=False,
        help="removes BPF filters from sniffer() but may impact performance",
    )
    optional.add_argument(
        "-V",
        "-v",
        "--version",
        action="version",
        version=f"rnrhelper {__version__}",
    )
    optional.add_argument(
        "--pytest",
        dest="pytest",
        action="store_true",
        default=False,
        help=argparse.SUPPRESS,
    )
    return parser
