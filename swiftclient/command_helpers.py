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

from swiftclient.utils import prt_bytes, split_request_headers


POLICY_HEADER_PREFIX = 'x-account-storage-policy-'


def stat_account(conn, options):
    items = []
    req_headers = split_request_headers(options.get('header', []))

    headers = conn.head_account(headers=req_headers)
    if options['verbose'] > 1:
        items.extend([
            ('StorageURL', conn.url),
            ('Auth Token', conn.token),
        ])
    container_count = int(headers.get('x-account-container-count', 0))
    object_count = prt_bytes(headers.get('x-account-object-count', 0),
                             options['human']).lstrip()
    bytes_used = prt_bytes(headers.get('x-account-bytes-used', 0),
                           options['human']).lstrip()
    items.extend([
        ('Account', conn.url.rsplit('/', 1)[-1]),
        ('Containers', container_count),
        ('Objects', object_count),
        ('Bytes', bytes_used),
    ])

    policies = set()
    for header_key, header_value in headers.items():
        if header_key.lower().startswith(POLICY_HEADER_PREFIX):
            policy_name = header_key.rsplit('-', 2)[0].split('-', 4)[-1]
            policies.add(policy_name)

    for policy in policies:
        container_count_header = (POLICY_HEADER_PREFIX + policy +
                                  '-container-count')
        if container_count_header in headers:
            items.append(
                ('Containers in policy "' + policy + '"',
                 prt_bytes(headers[container_count_header],
                           options['human']).lstrip())
            )
        items.extend((
            ('Objects in policy "' + policy + '"',
             prt_bytes(
                 headers.get(
                     POLICY_HEADER_PREFIX + policy + '-object-count', 0),
                 options['human']
             ).lstrip()),
            ('Bytes in policy "' + policy + '"',
             prt_bytes(
                 headers.get(
                     POLICY_HEADER_PREFIX + policy + '-bytes-used', 0),
                 options['human']
             ).lstrip()),
        ))

    return items, headers


def print_account_stats(items, headers, output_manager):
    exclude_policy_headers = []
    for header_key, header_value in headers.items():
        if header_key.lower().startswith(POLICY_HEADER_PREFIX):
            exclude_policy_headers.append(header_key)

    items.extend(headers_to_items(
        headers, meta_prefix='x-account-meta-',
        exclude_headers=([
            'content-length', 'date',
            'x-account-container-count',
            'x-account-object-count',
            'x-account-bytes-used'] + exclude_policy_headers)))

    # line up the items nicely
    offset = max(len(item) for item, value in items)
    output_manager.print_items(items, offset=offset)


def stat_container(conn, options, container):
    req_headers = split_request_headers(options.get('header', []))

    headers = conn.head_container(container, headers=req_headers)
    items = []

    if options['verbose'] > 1:
        path = '%s/%s' % (conn.url, container)
        items.extend([
            ('URL', path),
            ('Auth Token', conn.token)
        ])
    object_count = prt_bytes(
        headers.get('x-container-object-count', 0),
        options['human']).lstrip()
    bytes_used = prt_bytes(headers.get('x-container-bytes-used', 0),
                           options['human']).lstrip()
    items.extend([
        ('Account', conn.url.rsplit('/', 1)[-1]),
        ('Container', container),
        ('Objects', object_count),
        ('Bytes', bytes_used),
        ('Read ACL', headers.get('x-container-read', '')),
        ('Write ACL', headers.get('x-container-write', '')),
        ('Sync To', headers.get('x-container-sync-to', '')),
        ('Sync Key', headers.get('x-container-sync-key', ''))
    ])
    return items, headers


def print_container_stats(items, headers, output_manager):
    items.extend(headers_to_items(
        headers,
        meta_prefix='x-container-meta-',
        exclude_headers=(
            'content-length', 'date',
            'x-container-object-count',
            'x-container-bytes-used',
            'x-container-read',
            'x-container-write',
            'x-container-sync-to',
            'x-container-sync-key'
        )
    ))
    # line up the items nicely
    offset = max(len(item) for item, value in items)
    output_manager.print_items(items, offset=offset)


def stat_object(conn, options, container, obj):
    req_headers = split_request_headers(options.get('header', []))

    headers = conn.head_object(container, obj, headers=req_headers)
    items = []
    if options['verbose'] > 1:
        path = '%s/%s/%s' % (conn.url, container, obj)
        items.extend([
            ('URL', path),
            ('Auth Token', conn.token)
        ])
    content_length = prt_bytes(headers.get('content-length', 0),
                               options['human']).lstrip()
    items.extend([
        ('Account', conn.url.rsplit('/', 1)[-1]),
        ('Container', container),
        ('Object', obj),
        ('Content Type', headers.get('content-type')),
        ('Content Length', content_length),
        ('Last Modified', headers.get('last-modified')),
        ('ETag', headers.get('etag')),
        ('Manifest', headers.get('x-object-manifest'))
    ])
    return items, headers


def print_object_stats(items, headers, output_manager):
    items.extend(headers_to_items(
        headers,
        meta_prefix='x-object-meta-',
        exclude_headers=(
            'content-type', 'content-length',
            'last-modified', 'etag', 'date',
            'x-object-manifest')
    ))
    # line up the items nicely
    offset = max(len(item) for item, value in items)
    output_manager.print_items(items, offset=offset, skip_missing=True)


def headers_to_items(headers, meta_prefix='', exclude_headers=None):
    exclude_headers = exclude_headers or []
    other_items = []
    meta_items = []
    for key, value in headers.items():
        if key not in exclude_headers:
            if key.startswith(meta_prefix):
                meta_key = 'Meta %s' % key[len(meta_prefix):].title()
                meta_items.append((meta_key, value))
            else:
                other_items.append((key.title(), value))
    return meta_items + other_items
