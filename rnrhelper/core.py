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
rnrhelper.core
~~~~~~~~~~~~~~

the core neighbor has arrived
"""

import inspect
import logging
import multiprocessing as mp
import os
import signal
import sys
from datetime import datetime
from time import sleep

import scapy  # type: ignore

from rnrhelper.fakeap import Sniffer, TxBeacons
from rnrhelper.interface import Interface, InterfaceError

__PIDS = []
__PIDS.append(("main", os.getpid()))
__IFACE = Interface()


def removeVif() -> None:
    """Remove the vif we created if exists"""

    if __IFACE.requires_vif and not __IFACE.removed:
        logger = logging.getLogger(inspect.stack()[0][3])
        logger.debug("Removing monitor vif ...")
        __IFACE.reset_interface()
        __IFACE.removed = True


def receiveSignal(signum, _frame) -> None:
    """Handle noisy keyboardinterrupt"""
    logger = logging.getLogger(inspect.stack()[0][3])
    logger.debug(f"received signal {signum} with frame {_frame} ...")
    for name, pid in __PIDS:
        # We only want to print exit messages once as multiple processes close
        if name == "main" and os.getpid() == pid:
            if __IFACE.requires_vif:
                removeVif()
            if signum == 2:
                logger.warn("Detected SIGINT or Control-C ...")
            if signum == 15:
                logger.warn("Detected SIGTERM ...")


signal.signal(signal.SIGINT, receiveSignal)
signal.signal(signal.SIGTERM, receiveSignal)


def neighbor(args) -> None:
    """Won't you be my neighbor?"""
    logger = logging.getLogger(inspect.stack()[0][3])
    logger.debug(args)
    fake_ap_channel = 1
    fake_ap_ssid = "rnrhelper"
    fake_ap_interface = args.interface
    rnr_bssid = args.bssid
    rnr_oc = args.oc
    rnr_channel = args.channel
    rnr_ssid = args.ssid

    scapy_version = ""
    try:
        scapy_version = scapy.__version__
        logger.debug("scapy version is %s", scapy_version)
    except AttributeError:
        logger.exception("could not get version information from scapy.__version__")
        logger.debug("args: %s", args)
    if args.pytest:
        sys.exit("pytest")

    parent_pid = os.getpid()
    logger.debug("%s pid %s", __name__, parent_pid)

    boot_time = datetime.now().timestamp()
    lock = mp.Lock()
    sequence_number = mp.Value("i", 0)

    __IFACE.channel = 1
    __IFACE.frequency = 2412
    __IFACE.name = fake_ap_interface
    fake_ap_mac = ""
    try:
        if args.no_interface_prep:
            logger.warning(
                "user provided `--noprep` argument meaning profiler will not handle staging the interface"
            )
            # get channel from `iw`
            __IFACE.no_interface_prep = True
            # run interface setup
            __IFACE.setup()
            fake_ap_mac = __IFACE.mac
            logger.debug("finish interface setup with no staging ...")
        else:
            # run interface setup
            __IFACE.setup()
            fake_ap_mac = __IFACE.mac
            if __IFACE.requires_vif:
                # we require using a mon interface, update config so our subprocesses find it
                fake_ap_interface = __IFACE.mon

            # stage the interface
            __IFACE.stage_interface()
            logger.debug("finish interface setup and staging ...")
    except InterfaceError:
        logger.exception("problem interface staging ... exiting ...", exc_info=True)
        sys.exit(-1)

    running_processes = []
    finished_processes = []

    logger.info(
        f"Starting rnrhelper using {fake_ap_interface} ({fake_ap_mac}) on channel 1 (2412)"
    )

    logger.debug("beacon process")
    txbeacons = mp.Process(
        name="txbeacons",
        target=TxBeacons,
        args=(
            boot_time,
            fake_ap_ssid,
            fake_ap_interface,
            fake_ap_channel,
            rnr_bssid,
            rnr_oc,
            rnr_channel,
            rnr_ssid,
            lock,
            sequence_number,
        ),
    )
    running_processes.append(txbeacons)
    txbeacons.start()
    __PIDS.append(("txbeacons", txbeacons.pid))  # type: ignore

    logger.debug("sniffer process")
    sniffer = mp.Process(
        name="sniffer",
        target=Sniffer,
        args=(
            boot_time,
            fake_ap_ssid,
            fake_ap_interface,
            fake_ap_channel,
            rnr_bssid,
            rnr_oc,
            rnr_channel,
            rnr_ssid,
            lock,
            sequence_number,
            args.no_bpf_filters,
        ),
    )
    running_processes.append(sniffer)
    sniffer.start()
    __PIDS.append(("sniffer", sniffer.pid))  # type: ignore

    shutdown = False

    # keep main process alive until all subprocesses are finished or closed
    while running_processes:
        sleep(0.1)
        for process in running_processes:
            # if exitcode is None, it has not stopped yet.
            if process.exitcode is not None:
                if __IFACE.requires_vif and not __IFACE.removed:
                    removeVif()
                logger.debug("shutdown %s process (%s)", process.name, process.exitcode)
                running_processes.remove(process)
                finished_processes.append(process)
                shutdown = True

            if shutdown:
                process.kill()
                process.join()
