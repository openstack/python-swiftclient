# Copyright (c) 2010-2022 OpenStack, LLC.
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

import requests
from requests.sessions import merge_setting, merge_hooks
from requests.structures import CaseInsensitiveDict


class SwiftClientPreparedRequest(requests.PreparedRequest):
    def prepare_headers(self, headers):
        try:
            return super().prepare_headers(headers)
        except UnicodeError:
            # If we got an unicode error from the superclass's prepare_headers,
            # we had a non-spec-compliant non-ASCII header
            # (e.g. an UTF-8 encoded Swift object metadata header).
            # In that case, we just pass it through and hope nothing
            # bad will happen from not following the HTTP spec.
            self.headers = CaseInsensitiveDict(headers or {})


class SwiftClientRequestsSession(requests.Session):

    def prepare_request(self, request):
        # Close to the superclass's implementation,
        # but no cookies or .netrc authentication overrides here.
        p = SwiftClientPreparedRequest()
        headers = merge_setting(
            request.headers,
            self.headers,
            dict_class=CaseInsensitiveDict,
        )
        p.prepare(
            method=request.method.upper(),
            url=request.url,
            files=request.files,
            data=request.data,
            json=request.json,
            headers=headers,
            params=merge_setting(request.params, self.params),
            auth=merge_setting(request.auth, self.auth),
            cookies=None,
            hooks=merge_hooks(request.hooks, self.hooks),
        )
        return p
