# Copyright (c) 2010-2012 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Miscellaneous utility functions for use with Swift."""

import sys
import os

_ver = sys.version_info

#: Python 2.x?
is_py2 = (_ver[0] == 2)

#: Python 3.x?
is_py3 = (_ver[0] == 3)

if is_py2:
    from urllib import getproxies, proxy_bypass
elif is_py3:
    from urllib.request import getproxies, proxy_bypass


TRUE_VALUES = set(('true', '1', 'yes', 'on', 't', 'y'))


def config_true_value(value):
    """
    Returns True if the value is either True or a string in TRUE_VALUES.
    Returns False otherwise.
    This function come from swift.common.utils.config_true_value()
    """
    return value is True or \
        (isinstance(value, basestring) and value.lower() in TRUE_VALUES)


def prt_bytes(bytes, human_flag):
    """
    convert a number > 1024 to printable format, either in 4 char -h format as
    with ls -lh or return as 12 char right justified string
    """

    if human_flag:
        suffix = ''
        mods = list('KMGTPEZY')
        temp = float(bytes)
        if temp > 0:
            while (temp > 1023):
                try:
                    suffix = mods.pop(0)
                except IndexError:
                    break
                temp /= 1024.0
            if suffix != '':
                if temp >= 10:
                    bytes = '%3d%s' % (temp, suffix)
                else:
                    bytes = '%.1f%s' % (temp, suffix)
        if suffix == '':    # must be < 1024
            bytes = '%4s' % bytes
    else:
        bytes = '%12s' % bytes

    return(bytes)


# get_environ_proxies function, borrowed from python Requests
# (www.python-requests.org)
def get_environ_proxies(netloc):
    """Return a dict of environment proxies."""

    get_proxy = lambda k: os.environ.get(k) or os.environ.get(k.upper())

    # First check whether no_proxy is defined. If it is, check that the URL
    # we're getting isn't in the no_proxy list.
    no_proxy = get_proxy('no_proxy')

    if no_proxy:
        # We need to check whether we match here. We need to see if we match
        # the end of the netloc, both with and without the port.
        no_proxy = no_proxy.replace(' ', '').split(',')

        for host in no_proxy:
            if netloc.endswith(host) or netloc.split(':')[0].endswith(host):
                # The URL does match something in no_proxy, so we don't want
                # to apply the proxies on this URL.
                return {}

    # If the system proxy settings indicate that this URL should be bypassed,
    # don't proxy.
    if proxy_bypass(netloc):
        return {}

    # If we get here, we either didn't have no_proxy set or we're not going
    # anywhere that no_proxy applies to, and the system settings don't require
    # bypassing the proxy for the current URL.
    return getproxies()
