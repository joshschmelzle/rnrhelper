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
rnrhelper
~~~~~~~~~

a RNR helper for 6 GHz only APs
"""

import logging  # noqa
import os
import platform
import shutil
import sys

from rnrhelper.__version__ import __title__, __version__


def check_os():  # type: ignore
    """hard set no support for non linux platforms"""
    msg = """

{title} only works on Linux
""".format(
        title=__title__
    )
    if "linux" not in sys.platform:
        raise ValueError(msg)


PY_MAJOR = 3
PY_MINOR = 9
MINIMUM_PYTHON_VERISON = "3.9"


def check_python_version():  # type: ignore
    """Use old-school .format() method for if someone uses with very old Python"""
    msg = """

{title} version {pkgv} requires Python version {pyv} or higher.
""".format(
        title=__title__, pkgv=__version__, pyv=MINIMUM_PYTHON_VERISON
    )
    if sys.version_info < (PY_MAJOR, PY_MINOR):
        raise ValueError(msg)


__tools = [
    "tcpdump",
    "iw",
    "ip",
    "ethtool",
    "lspci",
    "lsusb",
    "modprobe",
    "modinfo",
    "wpa_cli",
]


def check_tools():  # type: ignore
    """are the required tools installed?"""
    for tool in __tools:
        if shutil.which(tool) is None:
            msg = """

It appears you do not have {tool} installed.

Please install using your distros package manager.
""".format(
                tool=tool
            )
            raise ValueError(msg)


def are_we_root() -> bool:
    """Do we have root permissions?"""
    if os.geteuid() == 0:
        return True
    else:
        return False


def main() -> None:
    """Set up args and start rnrhelper"""
    from . import core, helpers

    parser = helpers.setup_parser()
    args = parser.parse_args()
    if not are_we_root():
        raise PermissionError("\n\nrnrhelper must be run with root\n")
        sys.exit(-1)
    helpers.setup_logger(args)
    logger = logging.getLogger(__title__)
    logger.debug("%s version %s", __title__.split(".")[0], __version__)
    logger.debug("python platform version is %s", platform.python_version())
    logger.debug("beaming up scotty")
    core.neighbor(args)


def init() -> None:
    """Handle main init"""
    check_os()  # type: ignore
    check_python_version()  # type: ignore
    check_tools()  # type:ignore
    if __name__ == "__main__":
        main()
        sys.exit()


init()
