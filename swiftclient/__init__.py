# -*- encoding: utf-8 -*-
""""
OpenStack Swift Python client binding.
"""
from client import *
from swiftclient import version

__version__ = version.version_info.deferred_version_string()
