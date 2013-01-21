# -*- encoding: utf-8 -*-
""""
OpenStack Swift Python client binding.
"""
from client import *

# At setup.py time, we haven't installed anything yet, so there
# is nothing that is able to set this version property. Squelching
# that exception here should be fine- if there are problems with
# pkg_resources in a real install, that will manifest itself as
# an error still
try:
    from swiftclient import version

    __version__ = version.version_info.cached_version_string()
except Exception:
    pass
