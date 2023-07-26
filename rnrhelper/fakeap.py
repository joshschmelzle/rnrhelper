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
rnrhelper.fakeap
~~~~~~~~~~~~~~~~

fake ap code handling beaconing and sniffing 
"""

import binascii
import datetime
import inspect
import logging
import multiprocessing
import os
import signal
import sys
import zlib
from time import sleep, time

from rnrhelper.__version__ import __version__

# suppress scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


try:
    from scapy.all import Dot11Beacon  # type: ignore
    from scapy.all import Dot11Elt  # type: ignore
    from scapy.all import Dot11ProbeResp  # type: ignore
    from scapy.all import hexdump  # type: ignore
    from scapy.all import Dot11, RadioTap, Scapy_Exception  # type: ignore
    from scapy.all import conf as scapyconf  # type: ignore
    from scapy.all import get_if_hwaddr, get_if_raw_hwaddr, sniff  # type: ignore
except ModuleNotFoundError as error:
    logger = logging.getLogger("fakeap")
    if error.name == "scapy":
        logger.error("required module scapy not found.")
    else:
        logger.error(f"{error}")
    sys.exit(signal.SIGABRT)

from .constants import (
    DOT11_SUBTYPE_BEACON,
    DOT11_SUBTYPE_PROBE_REQ,
    DOT11_SUBTYPE_PROBE_RESP,
    DOT11_TYPE_MANAGEMENT,
)


class _Utils:
    """Fake AP helper functions"""

    @staticmethod
    def build_fake_frame_ies(
        fake_ap_ssid, fake_ap_channel, rnr_bssid, rnr_oc, rnr_channel, rnr_ssid
    ) -> Dot11Elt:
        """Build base frame for beacon and probe resp"""
        logger = logging.getLogger(inspect.stack()[0][1].split("/")[-1])

        fake_ap_ssid_bytes: "bytes" = bytes(fake_ap_ssid, "utf-8")
        essid = Dot11Elt(ID="SSID", info=fake_ap_ssid_bytes)

        rates_data = [140, 18, 152, 36, 176, 72, 96, 108]
        rates = Dot11Elt(ID="Rates", info=bytes(rates_data))

        fake_ap_channel_bytes = bytes([fake_ap_channel])  # type: ignore
        dsset = Dot11Elt(ID="DSset", info=fake_ap_channel_bytes)

        dtim_data = b"\x05\x04\x00\x03\x00\x00"
        dtim = Dot11Elt(ID="TIM", info=dtim_data)

        ht_cap_data = b"\xef\x19\x1b\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        ht_capabilities = Dot11Elt(ID=0x2D, info=ht_cap_data)

        rsn_data = b"\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x02\x80\x00"

        rsn = Dot11Elt(ID=0x30, info=rsn_data)

        ht_info_data = (
            fake_ap_channel_bytes
            + b"\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        )
        ht_information = Dot11Elt(ID=0x3D, info=ht_info_data)

        rm_enabled_data = b"\x02\x00\x00\x00\x00"
        rm_enabled_cap = Dot11Elt(ID=0x46, info=rm_enabled_data)

        extended_data = b"\x00\x00\x08\x00\x00\x00\x00\x40"
        extended = Dot11Elt(ID=0x7F, info=extended_data)

        _rnr_tbtt_info = b"\x00\x0d"
        logger.debug(f"rnr tbtt info: {_rnr_tbtt_info} len({len(_rnr_tbtt_info)})")

        _rnr_oc = int(rnr_oc).to_bytes(1, "big")
        logger.debug(f"rnr operating class: {_rnr_oc} len({len(_rnr_oc)})")

        _rnr_channel = int(rnr_channel).to_bytes(1, "big")
        logger.debug(f"rnr channel: {_rnr_channel} len({len(_rnr_channel)})")

        _rnr_tbtt_1_offset = int(255).to_bytes(1, "big")
        logger.debug(
            f"rnr tbtt 1 offset: {_rnr_tbtt_1_offset} len({len(_rnr_tbtt_1_offset)})"
        )

        _rnr_tbtt_1_bssid = bytes(binascii.unhexlify(f"{rnr_bssid}"))
        logger.debug(
            f"rnr tbtt 1 bssid: {_rnr_tbtt_1_bssid} len({len(_rnr_tbtt_1_bssid)})"
        )

        _rnr_tbtt_1_short_ssid = zlib.crc32(bytes(rnr_ssid, "utf-8")).to_bytes(4, "big")
        logger.debug(
            f"rnr tbtt 1 short ssid: {_rnr_tbtt_1_short_ssid} len({len(_rnr_tbtt_1_short_ssid)})"
        )

        _rnr_tbtt_1_params = b"\x08"
        logger.debug(
            f"rnr tbtt 1 params: {_rnr_tbtt_1_params} len({len(_rnr_tbtt_1_params)})"
        )

        _rnr_tbtt_1_psd_subfield = b"\x00"
        logger.debug(
            f"rnr tbtt 1 psd subfield: {_rnr_tbtt_1_psd_subfield} len({len(_rnr_tbtt_1_psd_subfield)})"
        )

        _rnr_tbtt_1 = (
            _rnr_tbtt_1_offset
            + _rnr_tbtt_1_bssid
            + _rnr_tbtt_1_short_ssid
            + _rnr_tbtt_1_params
            + _rnr_tbtt_1_psd_subfield
        )
        logger.debug(f"rnr tbtt 1: {_rnr_tbtt_1} len({len(_rnr_tbtt_1)})")

        _rnr_data = _rnr_tbtt_info + _rnr_oc + _rnr_channel + _rnr_tbtt_1
        logger.debug(f"rnr: {_rnr_data} len({len(_rnr_data)})")

        rnr = Dot11Elt(ID=0xC9, info=_rnr_data)
        logger.debug(f"rnr hexdump:\n f{hexdump(rnr, dump=True)}")

        he_cap_data = b"\x23\x0d\x01\x00\x02\x40\x00\x04\x70\x0c\x89\x7f\x03\x80\x04\x00\x00\x00\xaa\xaa\xaa\xaa\x7b\x1c\xc7\x71\x1c\xc7\x71\x1c\xc7\x71\x1c\xc7\x71"
        he_capabilities = Dot11Elt(ID=0xFF, info=he_cap_data)

        he_op_data = b"\x24\xf4\x3f\x00\x19\xfc\xff"
        he_operation = Dot11Elt(ID=0xFF, info=he_op_data)

        wmm_data = b"\x00\x50\xf2\x02\x01\x01\x8a\x00\x03\xa4\x00\x00\x27\xa4\x00\x00\x42\x43\x5e\x00\x62\x32\x2f\x00"
        wmm = Dot11Elt(ID=0xDD, info=wmm_data)

        package_info = bytes(f"rnrhelper version is {__version__}", "utf-8")
        package_len = len(package_info).to_bytes(1, "big")
        package_data = b"\x31\x41\x15\x92" + package_len + package_info
        package = Dot11Elt(ID=0xDD, info=package_data)

        frame = (
            essid
            / rates
            / dsset
            / dtim
            / ht_capabilities
            / rsn
            / ht_information
            / rm_enabled_cap
            / extended
            / rnr
            / he_capabilities
            / he_operation
            / wmm
            / package
        )

        return frame

    @staticmethod
    def get_mac(interface: str) -> str:
        """Get the mac address for a specified interface"""
        try:
            mac = get_if_hwaddr(interface)
        except Scapy_Exception:
            mac = ":".join(format(x, "02x") for x in get_if_raw_hwaddr(interface)[1])
        return mac

    @staticmethod
    def next_sequence_number(sequence_number) -> int:
        """Update a sequence number of type multiprocessing Value"""
        sequence_number.value = (sequence_number.value + 1) % 4096
        return sequence_number.value


class TxBeacons(multiprocessing.Process):
    """Handle Tx of fake AP frames"""

    def __init__(
        self,
        boot_time: datetime.datetime,
        fake_ap_ssid,
        fake_ap_interface,
        fake_ap_channel,
        rnr_bssid,
        rnr_oc,
        rnr_channel,
        rnr_ssid,
        lock,
        sequence_number,
    ):
        super(TxBeacons, self).__init__()
        self.logger = logging.getLogger(inspect.stack()[0][1].split("/")[-1])
        self.logger.debug("beacon pid: %s; parent pid: %s", os.getpid(), os.getppid())
        self.boot_time = boot_time
        self.logger.debug("boot time: %s", boot_time)
        self.sequence_number = sequence_number
        self.ssid = fake_ap_ssid
        self.interface = fake_ap_interface
        self.channel = fake_ap_channel
        self.rnr_bssid = rnr_bssid
        self.rnr_oc = rnr_oc
        self.rnr_channel = rnr_channel
        self.rnr_ssid = rnr_ssid
        scapyconf.iface = self.interface
        self.l2socket = None
        try:
            self.l2socket = scapyconf.L2socket(iface=self.interface)
        except OSError as error:
            if "No such device" in error.strerror:
                self.logger.warning(
                    "TxBeacons: no such device (%s) ... exiting ...", self.interface
                )
                sys.exit(signal.SIGALRM)
        if not self.l2socket:
            self.logger.error(
                "TxBeacons(): unable to create L2socket with %s ... exiting ...",
                self.interface,
            )
            sys.exit(signal.SIGALRM)
        self.logger.debug(self.l2socket.outs)
        self.beacon_interval = 0.102_400

        with lock:
            self.mac = _Utils.get_mac(self.interface)
            dot11 = Dot11(
                type=DOT11_TYPE_MANAGEMENT,
                subtype=DOT11_SUBTYPE_BEACON,
                addr1="ff:ff:ff:ff:ff:ff",
                addr2=self.mac,
                addr3=self.mac,
            )
            dot11beacon = Dot11Beacon(cap=0x1111)
            beacon_frame_ies = _Utils.build_fake_frame_ies(
                self.ssid, self.channel, rnr_bssid, rnr_oc, rnr_channel, rnr_ssid
            )
            self.beacon_frame = RadioTap() / dot11 / dot11beacon / beacon_frame_ies

        self.logger.debug(
            f"origin beacon hexdump {hexdump(self.beacon_frame, dump=True)}"
        )
        self.logger.info("starting beacon transmissions")
        self.every(self.beacon_interval, self.beacon)

    def every(self, interval: float, task) -> None:
        """Attempt to address beacon drift"""
        start_time = time()
        while True:
            task()
            sleep(interval - ((time() - start_time) % interval))

    def beacon(self) -> None:
        """Update and Tx Beacon Frame"""
        frame = self.beacon_frame
        with self.sequence_number.get_lock():
            frame.sequence_number = _Utils.next_sequence_number(self.sequence_number)

        try:
            self.l2socket.send(frame)  # type: ignore
        except OSError as error:
            for event in ("Network is down", "No such device"):
                if event in error.strerror:
                    self.logger.warning(
                        "beacon(): network is down or no such device (%s) ... exiting ...",
                        self.interface,
                    )
                    sys.exit(signal.SIGALRM)


class Sniffer(multiprocessing.Process):
    """Handle sniffing probes"""

    def __init__(
        self,
        boot_time: datetime.datetime,
        fake_ap_ssid,
        fake_ap_interface,
        fake_ap_channel,
        rnr_bssid,
        rnr_oc,
        rnr_channel,
        rnr_ssid,
        lock,
        sequence_number,
        no_bpf_filters,
    ):
        super(Sniffer, self).__init__()
        self.logger = logging.getLogger(inspect.stack()[0][1].split("/")[-1])
        self.logger.debug("sniffer pid: %s; parent pid: %s", os.getpid(), os.getppid())

        self.boot_time = boot_time
        self.ssid = fake_ap_ssid
        self.interface = fake_ap_interface
        self.channel = fake_ap_channel
        self.rnr_bssid = rnr_bssid
        self.rnr_oc = rnr_oc
        self.rnr_channel = rnr_channel
        self.rnr_ssid = rnr_ssid
        self.no_bpf_filters = no_bpf_filters
        self.sequence_number = sequence_number

        self.bpf_filter = "type mgt subtype probe-req"
        if self.no_bpf_filters:
            self.bpf_filter = ""
        # mgt bpf filter: assoc-req, assoc-resp, reassoc-req, reassoc-resp, probe-req, probe-resp, beacon, atim, disassoc, auth, deauth
        # ctl bpf filter: ps-poll, rts, cts, ack, cf-end, cf-end-ack
        scapyconf.iface = self.interface
        # self.logger.debug(scapyconf.ifaces)
        self.l2socket = None
        try:
            self.l2socket = scapyconf.L2socket(iface=self.interface)
        except OSError as error:
            if "No such device" in error.strerror:
                self.logger.warning(
                    "Sniffer: No such device (%s) ... exiting ...", self.interface
                )
                sys.exit(signal.SIGALRM)
        if not self.l2socket:
            self.logger.error(
                "Sniffer(): unable to create L2socket with %s ... exiting ...",
                self.interface,
            )
            sys.exit(signal.SIGALRM)
        self.logger.debug(self.l2socket.outs)

        self.received_frame_cb = self.received_frame
        self.dot11_probe_request_cb = self.probe_response
        with lock:
            probe_resp_ies = _Utils.build_fake_frame_ies(
                self.ssid, self.channel, rnr_bssid, rnr_oc, rnr_channel, rnr_ssid
            )
            self.mac = _Utils.get_mac(self.interface)
            self.probe_response_frame = (
                RadioTap()
                / Dot11(
                    subtype=DOT11_SUBTYPE_PROBE_RESP, addr2=self.mac, addr3=self.mac
                )
                / Dot11ProbeResp(cap=0x1111)
                / probe_resp_ies
            )

        try:
            sniff(
                iface=self.interface,
                prn=self.received_frame_cb,
                store=0,
                filter=self.bpf_filter,
            )
        except Scapy_Exception as error:
            if "ailed to compile filter" in str(error):
                self.logger.exception(
                    "we had a problem creating BPF filters on L2socket/%s",
                    self.interface,
                    exc_info=True,
                )
                self.logger.info("try running with --no_bpf_filters")
            else:
                self.logger.exception(
                    "scappy.sniff() problem in fakeap.py sniffer(): %s",
                    exc_info=True,
                )
            signal.SIGALRM

    def received_frame(self, packet) -> None:
        """Handle incoming packets for rnrhelper"""
        if packet.subtype == DOT11_SUBTYPE_PROBE_REQ:
            if Dot11Elt in packet:
                ssid = packet[Dot11Elt].info
                # self.logger.debug("probe req for %s by MAC %s", ssid, packet.addr)
                if ssid == self.ssid or packet[Dot11Elt].len == 0:
                    self.dot11_probe_request_cb(packet)

    def probe_response(self, probe_request) -> None:
        """Send probe resp to assist with 6 GHz discovery"""
        frame = self.probe_response_frame
        with self.sequence_number.get_lock():
            frame.sequence_number = _Utils.next_sequence_number(self.sequence_number)
        frame[Dot11].addr1 = probe_request.addr2
        try:
            self.l2socket.send(frame)  # type: ignore
            self.logger.debug("sent probe resp to %s", probe_request.addr2)
        except OSError as error:
            for event in ("Network is down", "No such device"):
                if event in error.strerror:
                    self.logger.exception(
                        "probe_response(): network is down or no such device ... exiting ..."
                    )
                    sys.exit(signal.SIGALRM)
