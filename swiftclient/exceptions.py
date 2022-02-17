# Copyright (c) 2010-2013 OpenStack, LLC.
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

import urllib


class ClientException(Exception):

    def __init__(self, msg, http_scheme='', http_host='', http_port='',
                 http_path='', http_query='', http_status=None, http_reason='',
                 http_device='', http_response_content='',
                 http_response_headers=None):
        super(ClientException, self).__init__(msg)
        self.msg = msg
        self.http_scheme = http_scheme
        self.http_host = http_host
        self.http_port = http_port
        self.http_path = http_path
        self.http_query = http_query
        self.http_status = http_status
        self.http_reason = http_reason
        self.http_device = http_device
        self.http_response_content = http_response_content
        self.http_response_headers = http_response_headers

        self.transaction_id = None
        if self.http_response_headers:
            for header in ('X-Trans-Id', 'X-Openstack-Request-Id'):
                if header in self.http_response_headers:
                    self.transaction_id = self.http_response_headers[header]
                    break

    @classmethod
    def from_response(cls, resp, msg=None, body=None):
        msg = msg or '%s %s' % (resp.status_code, resp.reason)
        body = body or resp.content
        parsed_url = urllib.parse.urlparse(resp.request.url)
        return cls(msg, parsed_url.scheme, parsed_url.hostname,
                   parsed_url.port, parsed_url.path, parsed_url.query,
                   resp.status_code, resp.reason, '', body, resp.headers)

    def __str__(self):
        a = self.msg
        b = ''
        if self.http_scheme:
            b += '%s://' % self.http_scheme
        if self.http_host:
            b += self.http_host
        if self.http_port:
            b += ':%s' % self.http_port
        if self.http_path:
            b += self.http_path
        if self.http_query:
            b += '?%s' % self.http_query
        if self.http_status:
            if b:
                b = '%s %s' % (b, self.http_status)
            else:
                b = str(self.http_status)
        if self.http_reason:
            if b:
                b = '%s %s' % (b, self.http_reason)
            else:
                b = '- %s' % self.http_reason
        if self.http_device:
            if b:
                b = '%s: device %s' % (b, self.http_device)
            else:
                b = 'device %s' % self.http_device
        if self.http_response_content:
            if len(self.http_response_content) <= 60:
                b += '   %s' % self.http_response_content
            else:
                b += '  [first 60 chars of response] %s' \
                    % self.http_response_content[:60]
        c = ''
        if self.transaction_id:
            c = ' (txn: %s)' % self.transaction_id
        return b and '%s: %s%s' % (a, b, c) or (a + c)
