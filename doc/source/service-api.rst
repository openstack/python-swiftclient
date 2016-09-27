================================
The swiftclient.SwiftService API
================================

A higher-level API aimed at allowing developers an easy way to perform multiple
operations asynchronously using a configurable thread pool. Documentation for
each service method call can be found here: :mod:`swiftclient.service`.

Authentication
--------------

This section covers the various options for authenticating with a swift
object store. The combinations of options required for each authentication
version are detailed below. Once again, these are just a subset of those that
can be used to successfully authenticate, but they are the most common and
recommended.

The relevant authentication options are presented as python dictionaries that
should be added to any other options you are supplying to your ``SwiftService``
instance. As indicated in the python code, you can also set these options as
environment variables that will be loaded automatically if the relevant option
is not specified.

The ``SwiftService`` authentication attempts to automatically select
the auth version based on the combination of options specified, but
supplying options from multiple different auth versions can cause unexpected
behaviour.

  .. note::

     Leftover environment variables are a common source of confusion when
     authorization fails.

Keystone V3
~~~~~~~~~~~

.. code-block:: python

    {
        ...
        "auth_version": environ.get('ST_AUTH_VERSION'),  # Should be '3'
        "os_username": environ.get('OS_USERNAME'),
        "os_password": environ.get('OS_PASSWORD'),
        "os_project_name": environ.get('OS_PROJECT_NAME'),
        "os_project_domain_name": environ.get('OS_PROJECT_DOMAIN_NAME'),
        "os_auth_url": environ.get('OS_AUTH_URL'),
        ...
    }

.. code-block:: python

    {
        ...
        "auth_version": environ.get('ST_AUTH_VERSION'),  # Should be '3'
        "os_username": environ.get('OS_USERNAME'),
        "os_password": environ.get('OS_PASSWORD'),
        "os_project_id": environ.get('OS_PROJECT_ID'),
        "os_project_domain_id": environ.get('OS_PROJECT_DOMAIN_ID'),
        "os_auth_url": environ.get('OS_AUTH_URL'),
        ...
    }

Keystone V2
~~~~~~~~~~~

.. code-block:: python

    {
        ...
        "auth_version": environ.get('ST_AUTH_VERSION'),  # Should be '2.0'
        "os_username": environ.get('OS_USERNAME'),
        "os_password": environ.get('OS_PASSWORD'),
        "os_tenant_name": environ.get('OS_TENANT_NAME'),
        "os_auth_url": environ.get('OS_AUTH_URL'),
        ...
    }

Legacy Auth
~~~~~~~~~~~

.. code-block:: python

    {
        ...
        "auth_version": environ.get('ST_AUTH_VERSION'),  # Should be '1.0'
        "auth": environ.get('ST_AUTH'),
        "user": environ.get('ST_USER'),
        "key": environ.get('ST_KEY'),
        ...
    }

Configuration
-------------

When you create an instance of a ``SwiftService``, you can override a collection
of default options to suit your use case. Typically, the defaults are sensible to
get us started, but depending on your needs you might want to tweak them to
improve performance (options affecting large objects and thread counts can
significantly alter performance in the right situation).

Service level defaults and some extra options can also be overridden on a
per-operation (or even in some cases per-object) basis, and you will call out
which options affect which operations later in the document.

The configuration of the service API is performed using an options dictionary
passed to the ``SwiftService`` during initialisation. The options available
in this dictionary are described below, along with their defaults:

Options
~~~~~~~

    ``retries``: ``5``
        The number of times that the library should attempt to retry HTTP
        actions before giving up and reporting a failure.

    ``container_threads``: ``10``

    ``object_dd_threads``: ``10``

    ``object_uu_threads``: ``10``

    ``segment_threads``: ``10``
        The above options determine the size of the available thread pools for
        performing swift operations. Container operations (such as listing a
        container) operate in the container threads, and a similar pattern
        applies to object and segment threads.

        .. note::

           Object threads are separated into two separate thread pools:
           ``uu`` and ``dd``. This stands for "upload/update" and "download/delete",
           and the corresponding actions will be run on separate threads pools.

    ``segment_size``: ``None``
        If specified, this option enables uploading of large objects. Should the
        object being uploaded be larger than 5G in size, this option is
        mandatory otherwise the upload will fail. This option should be
        specified as a size in bytes.

    ``use_slo``: ``False``
        Used in combination with the above option, ``use_slo`` will upload large
        objects as static rather than dynamic. Only static large objects provide
        error checking for the downloaded object, so we recommend this option.

    ``segment_container``: ``None``
        Allows the user to select the container into which large object segments
        will be uploaded. We do not recommend changing this value as it could make
        locating orphaned segments more difficult in the case of errors.

    ``leave_segments``: ``False``
        Setting this option to true means that when deleting or overwriting a large
        object, its segments will be left in the object store and must be cleaned
        up manually. This option can be useful when sharing large object segments
        between multiple objects in more advanced scenarios, but must be treated
        with care, as it could lead to ever increasing storage usage.

    ``changed``: ``None``
        This option affects uploads and simply means that those objects which
        already exist in the object store will not be overwritten if the ``mtime``
        and size of the source is the same as the existing object.

    ``skip_identical``: ``False``
        A slightly more thorough case of the above, but rather than ``mtime`` and size
        uses an object's ``MD5 sum``.

    ``yes_all``: ``False``
        This options affects only download and delete, and in each case must be
        specified in order to download/delete the entire contents of an account.
        This option has no effect on any other calls.

    ``no_download``: ``False``
        This option only affects download and means that all operations proceed as
        normal with the exception that no data is written to disk.

    ``header``: ``[]``
        Used with upload and post operations to set headers on objects. Headers
        are specified as colon separated strings, e.g. "content-type:text/plain".

    ``meta``: ``[]``
        Used to set metadata on an object similarly to headers.

        .. note::
           Setting metadata is a destructive operation, so when updating one
           of many metadata values all desired metadata for an object must be re-applied.

    ``long``: ``False``
        Affects only list operations, and results in more metrics being made
        available in the results at the expense of lower performance.

    ``fail_fast``: ``False``
        Applies to delete and upload operations, and attempts to abort queued
        tasks in the event of errors.

    ``prefix``: ``None``
        Affects list operations; only objects with the given prefix will be
        returned/affected. It is not advisable to set at the service level, as
        those operations that call list to discover objects on which they should
        operate will also be affected.

    ``delimiter``: ``None``
        Affects list operations, and means that listings only contain results up
        to the first instance of the delimiter in the object name. This is useful
        for working with objects containing '/' in their names to simulate folder
        structures.

    ``dir_marker``: ``False``
        Affects uploads, and allows empty 'pseudofolder' objects to be created
        when the source of an upload is ``None``.

    ``checksum``: ``True``
        Affects uploads and downloads. If set check md5 sum for the transfer.

    ``shuffle``: ``False``
        When downloading objects, the default behaviour of the CLI is to shuffle
        lists of objects in order to spread the load on storage drives when multiple
        clients are downloading the same files to multiple locations (e.g. in the
        event of distributing an update). When using the ``SwiftService`` directly,
        object downloads are scheduled in the same order as they appear in the container
        listing. When combined with a single download thread this means that objects
        are downloaded in lexically-sorted order. Setting this option to ``True``
        gives the same shuffling behaviour as the CLI.

    ``destination``: ``None``
        When copying objects, this specifies the destination where the object
        will be copied to.  The default of None means copy will be the same as
        source.

    ``fresh_metadata``: ``None``
        When copying objects, this specifies that the object metadata on the
        source will *not* be applied to the destination object - the
        destination object will have a new fresh set of metadata that includes
        *only* the metadata specified in the meta option if any at all.

Other available options can be found in ``swiftclient/service.py`` in the
source code for ``python-swiftclient``. Each ``SwiftService`` method also allows
for an optional dictionary to override those specified at init time, and the
appropriate docstrings show which options modify each method's behaviour.

Available Operations
--------------------

Each operation provided by the service API may raise a ``SwiftError`` or
``ClientException`` for any call that fails completely (or a call which
performs only one operation at an account or container level). In the case of a
successful call an operation returns one of the following:

* A dictionary detailing the results of a single operation.
* An iterator that produces result dictionaries (for calls that perform
  multiple sub-operations).

A result dictionary can indicate either the success or failure of an individual
operation (detailed in the ``success`` key), and will either contain the
successful result, or an ``error`` key detailing the error encountered
(usually an instance of Exception).

An example result dictionary is given below:

.. code-block:: python

    result = {
        'action': 'download_object',
        'success': True,
        'container': container,
        'object': obj,
        'path': path,
        'start_time': start_time,
        'finish_time': finish_time,
        'headers_receipt': headers_receipt,
        'auth_end_time': conn.auth_end_time,
        'read_length': bytes_read,
        'attempts': conn.attempts
    }

All the possible ``action`` values are detailed below:

.. code-block:: python

    [
        'stat_account',
        'stat_container',
        'stat_object',
        'post_account',
        'post_container',
        'post_object',
        'list_part',          # list yields zero or more 'list_part' results
        'download_object',
        'create_container',   # from upload
        'create_dir_marker',  # from upload
        'upload_object',
        'upload_segment',
        'delete_container',
        'delete_object',
        'delete_segment',     # from delete_object operations
        'capabilities',
    ]

Stat
~~~~

Stat can be called against an account, a container, or a list of objects to
get account stats, container stats or information about the given objects. In
the first two cases a dictionary is returned containing the results of the
operation, and in the case of a list of object names being supplied, an
iterator over the results generated for each object is returned.

Information returned includes the amount of data used by the given
object/container/account and any headers or metadata set (this includes
user set data as well as content-type and modification times).

See :mod:`swiftclient.service.SwiftService.stat` for docs generated from the
method docstring.

Valid calls for this method are as follows:

* ``stat([options])``: Returns stats for the configured account.
* ``stat(<container>, [options])``: Returns stats for the given container.
* ``stat(<container>, <object_list>, [options])``: Returns stats for each
  of the given objects in the given container (through the returned
  iterator).

Results from stat are dictionaries indicating the success or failure of each
operation. In the case of a successful stat against an account or container,
the method returns immediately with one of the following results:

.. code-block:: python

    {
        'action': 'stat_account',
        'success': True,
        'items': items,
        'headers': headers
    }

.. code-block:: python

    {
        'action': 'stat_container',
        'container': <container>,
        'success': True,
        'items': items,
        'headers': headers
    }

In the case of stat called against a list of objects, the method returns a
generator that returns the results of individual object stat operations as they
are performed on the thread pool:

.. code-block:: python

    {
        'action': 'stat_object',
        'object': <object_name>,
        'container': <container>,
        'success': True,
        'items': items,
        'headers': headers
    }

In the case of a failure the dictionary returned will indicate that the
operation was not successful, and will include the keys below:

.. code-block:: python

    {
        'action': <'stat_object'|'stat_container'|'stat_account'>,
        'object': <'object_name'>,      # Only for stat with objects list
        'container': <container>,       # Only for stat with objects list or container
        'success': False,
        'error': <error>,
        'traceback': <trace>,
        'error_timestamp': <timestamp>
    }

.. topic:: Example

   The code below demonstrates the use of ``stat`` to retrieve the headers for
   a given list of objects in a container using 20 threads. The code creates a
   mapping from object name to headers which is then pretty printed to the log.

   .. literalinclude:: ../../examples/stat.py
      :language: python

List
~~~~

List can be called against an account or a container to retrieve the containers
or objects contained within them. Each call returns an iterator that returns
pages of results (by default, up to 10000 results in each page).

See :mod:`swiftclient.service.SwiftService.list` for docs generated from the
method docstring.

If the given container or account does not exist, the list method will raise
a ``SwiftError``, but for all other success/failures a dictionary is returned.
Each successfully listed page returns a dictionary as described below:

.. code-block:: python

    {
        'action': <'list_account_part'|'list_container_part'>,
        'container': <container>,      # Only for listing a container
        'prefix': <prefix>,            # The prefix of returned objects/containers
        'success': True,
        'listing': [Item],             # A list of results
                                       # (only in the event of success)
        'marker': <marker>             # The last item name in the list
                                       # (only in the event of success)
    }

Where an item contains the following keys:

.. code-block:: python

    {
        'name': <name>,
        'bytes': 10485760,
        'last_modified': '2014-12-11T12:02:38.774540',
        'hash': 'fb938269cbeabe4c234e1127bbd3b74a',
        'content_type': 'application/octet-stream',
        'meta': <metadata>    # Full metadata listing from stat'ing each object
                              # this key only exists if 'long' is specified in options
    }

Any failure listing an account or container that exists will return a failure
dictionary as described below:

.. code-block:: python

    {
        'action': <'list_account_part'|'list_container_part'>,,
        'container': container,         # Only for listing a container
        'prefix': options['prefix'],
        'success': success,
        'marker': marker,
        'error': error,
        'traceback': <trace>,
        'error_timestamp': <timestamp>
    }

.. topic:: Example

   The code below demonstrates the use of ``list`` to list all items in a
   container that are over 10MiB in size:

   .. literalinclude:: ../../examples/list.py
      :language: python

Post
~~~~

Post can be called against an account, container or list of objects in order to
update the metadata attached to the given items. In the first two cases a single
dictionary is returned containing the results of the operation, and in the case
of a list of objects being supplied, an iterator over the results generated for
each object post is returned.

Each element of the object list may be a plain string of the object name, or a
``SwiftPostObject`` that allows finer control over the options and metadata
applied to each of the individual post operations. When a string is given for
the object name, the options and metadata applied are a combination of those
supplied to the call to ``post()`` and the defaults of the ``SwiftService``
object.

If the given container or account does not exist, the ``post`` method will
raise a ``SwiftError``. Successful metadata update results are dictionaries as
described below:

.. code-block:: python

    {
        'action': <'post_account'|'post_container'|'post_object'>,
        'success': True,
        'container': <container>,
        'object': <object>,
        'headers': {},
        'response_dict': <HTTP response details>
    }

.. note::
    Updating user metadata keys will not only add any specified keys, but
    will also remove user metadata that has previously been set. This means
    that each time user metadata is updated, the complete set of desired
    key-value pairs must be specified.

.. topic:: Example

   The code below demonstrates the use of ``post`` to set an archive folder in
   a given container to expire after a 24 hour delay:

   .. literalinclude:: ../../examples/post.py
      :language: python

Download
~~~~~~~~

Download can be called against an entire account, a single container, or a list
of objects in a given container. Each element of the object list is a string
detailing the full name of an object to download.

In order to download the full contents of an entire account, you must set the
value of ``yes_all`` to ``True`` in the ``options`` dictionary supplied to
either the ``SwiftService`` instance or the call to ``download``.

If the given container or account does not exist, the ``download`` method will
raise a ``SwiftError``, otherwise an iterator over the results generated for
each object download is returned.

See :mod:`swiftclient.service.SwiftService.download` for docs generated from the
method docstring.

For each successfully downloaded object, the results returned by the iterator
will be a dictionary as described below (results are not returned for completed
container or object segment downloads):

.. code-block:: python

    {
        'action': 'download_object',
        'container': <container>,
        'object': <object name>,
        'success': True,
        'path': <local path to downloaded object>,
        'pseudodir': <if true, the download created an empty directory>,
        'start_time': <time download started>,
        'end_time': <time download completed>,
        'headers_receipt': <time the headers from the object were retrieved>,
        'auth_end_time': <time authentication completed>,
        'read_length': <bytes_read>,
        'attempts': <attempt count>,
        'response_dict': <HTTP response details>
    }

Any failure uploading an object will return a failure dictionary as described
below:

.. code-block:: python

    {
        'action': 'download_object',
        'container': <container>,
        'object': <object name>,
        'success': False,
        'path': <local path of the failed download>,
        'pseudodir': <if true, the failed download was an empty directory>,
        'attempts': <attempt count>,
        'error': <error>,
        'traceback': <trace>,
        'error_timestamp': <timestamp>,
        'response_dict': <HTTP response details>
    }

.. topic:: Example

   The code below demonstrates the use of ``download`` to download all PNG
   images from a dated archive folder in a given container:

   .. literalinclude:: ../../examples/download.py
      :language: python

Upload
~~~~~~

Upload is always called against an account and container and with a list of
objects to upload. Each element of the object list may be a plain string
detailing the path of the object to upload, or a ``SwiftUploadObject`` that
allows finer control over some aspects of the individual operations.

When a simple string is supplied to specify a file to upload, the name of the
object uploaded is the full path of the specified file and the options used for
the upload are those supplied to the call to ``upload``.

Constructing a ``SwiftUploadObject`` allows the user to supply an object name
for the uploaded file, and modify the options used by ``upload`` at the
granularity of individual files.

If the given container or account does not exist, the ``upload`` method will
raise a ``SwiftError``, otherwise an iterator over the results generated for
each object upload is returned.

See :mod:`swiftclient.service.SwiftService.upload` for docs generated from the
method docstring.

For each successfully uploaded object (or object segment), the results returned
by the iterator will be a dictionary as described below:

.. code-block:: python

    {
        'action': 'upload_object',
        'container': <container>,
        'object': <object name>,
        'success': True,
        'status': <'uploaded'|'skipped-identical'|'skipped-changed'>,
        'attempts': <attempt count>,
        'response_dict': <HTTP response details>
    }

    {
        'action': 'upload_segment',
        'for_container': <container>,
        'for_object': <object name>,
        'segment_index': <segment_index>,
        'segment_size': <segment_size>,
        'segment_location': <segment_path>
        'segment_etag': <etag>,
        'log_line': <object segment n>
        'success': True,
        'response_dict': <HTTP response details>,
        'attempts': <attempt count>
    }

Any failure uploading an object will return a failure dictionary as described
below:

.. code-block:: python

    {
        'action': 'upload_object',
        'container': <container>,
        'object': <object name>,
        'success': False,
        'attempts': <attempt count>,
        'error': <error>,
        'traceback': <trace>,
        'error_timestamp': <timestamp>,
        'response_dict': <HTTP response details>
    }

    {
        'action': 'upload_segment',
        'for_container': <container>,
        'for_object': <object name>,
        'segment_index': <segment_index>,
        'segment_size': <segment_size>,
        'segment_location': <segment_path>,
        'log_line': <object segment n>,
        'success': False,
        'error': <error>,
        'traceback': <trace>,
        'error_timestamp': <timestamp>,
        'response_dict': <HTTP response details>,
        'attempts': <attempt count>
    }

.. topic:: Example

   The code below demonstrates the use of ``upload`` to upload all files and
   folders in a given directory, and rename each object by replacing the root
   directory name with 'my-<d>-objects', where <d> is the name of the uploaded
   directory:

   .. literalinclude:: ../../examples/upload.py
      :language: python

Delete
~~~~~~

Delete can be called against an account or a container to remove the containers
or objects contained within them. Each call to ``delete`` returns an iterator
over results of each resulting sub-request.

If the number of requested delete operations is large and the target swift
cluster is running the bulk middleware, the call to ``SwiftService.delete`` will
make use of bulk operations and the returned result iterator will return
``bulk_delete`` results rather than individual ``delete_object``,
``delete_container`` or ``delete_segment`` results.

See :mod:`swiftclient.service.SwiftService.delete` for docs generated from the
method docstring.

For each successfully deleted container, object or segment, the results returned
by the iterator will be a dictionary as described below:

.. code-block:: python

    {
        'action': <'delete_object'|'delete_segment'>,
        'container': <container>,
        'object': <object name>,
        'success': True,
        'attempts': <attempt count>,
        'response_dict': <HTTP response details>
    }

    {
        'action': 'delete_container',
        'container': <container>,
        'success': True,
        'response_dict': <HTTP response details>,
        'attempts': <attempt count>
    }

    {
        'action': 'bulk_delete',
        'container': <container>,
        'objects': <[objects]>,
        'success': True,
        'attempts': <attempt count>,
        'response_dict': <HTTP response details>
    }

Any failure in a delete operation will return a failure dictionary as described
below:

.. code-block:: python

    {
        'action': ('delete_object'|'delete_segment'),
        'container': <container>,
        'object': <object name>,
        'success': False,
        'attempts': <attempt count>,
        'error': <error>,
        'traceback': <trace>,
        'error_timestamp': <timestamp>,
        'response_dict': <HTTP response details>
    }

    {
        'action': 'delete_container',
        'container': <container>,
        'success': False,
        'error': <error>,
        'traceback': <trace>,
        'error_timestamp': <timestamp>,
        'response_dict': <HTTP response details>,
        'attempts': <attempt count>
    }

    {
        'action': 'bulk_delete',
        'container': <container>,
        'objects': <[objects]>,
        'success': False,
        'attempts': <attempt count>,
        'error': <error>,
        'traceback': <trace>,
        'error_timestamp': <timestamp>,
        'response_dict': <HTTP response details>
    }

.. topic:: Example

   The code below demonstrates the use of ``delete`` to remove a given list of
   objects from a specified container. As the objects are deleted the
   transaction ID of the relevant request is printed along with the object name
   and number of attempts required. By printing the transaction ID, the printed
   operations can be easily linked to events in the swift server logs:

   .. literalinclude:: ../../examples/delete.py
      :language: python

Copy
~~~~

Copy can be called to copy an object or update the metadata on the given items.

Each element of the object list may be a plain string of the object name, or a
``SwiftCopyObject`` that allows finer control over the options applied to each
of the individual copy operations (destination, fresh_metadata, options).

Destination should be in format /container/object; if not set, the object will be
copied onto itself. Fresh_metadata sets mode of operation on metadata. If not set,
current object user metadata will be copied/preserved; if set, all current user
metadata will be removed.

Returns an iterator over the results generated for each object copy (and may
also include the results of creating destination containers).

When a string is given for the object name, destination and fresh metadata will
default to None and None, which result in adding metadata to existing objects.

Successful copy results are dictionaries as described below:

.. code-block:: python

   {
       'action': 'copy_object',
       'success': True,
       'container': <container>,
       'object': <object>,
       'destination': <destination>,
       'headers': {},
       'fresh_metadata': <boolean>,
       'response_dict': <HTTP response details>
   }

Any failure in a copy operation will return a failure dictionary as described
below:

.. code-block:: python

   {
       'action': 'copy_object',
       'success': False,
       'container': <container>,
       'object': <object>,
       'destination': <destination>,
       'headers': {},
       'fresh_metadata': <boolean>,
       'response_dict': <HTTP response details>,
       'error': <error>,
       'traceback': <traceback>,
       'error_timestamp': <timestamp>
   }

.. topic:: Example

   The code below demonstrates the use of ``copy`` to add new user metadata for
   objects a and b, and to copy object c to d (with added metadata).

   .. literalinclude:: ../../examples/copy.py
      :language: python

Capabilities
~~~~~~~~~~~~

Capabilities can be called against an account or a particular proxy URL in
order to determine the capabilities of the swift cluster. These capabilities
include details about configuration options and the middlewares that are
installed in the proxy pipeline.

See :mod:`swiftclient.service.SwiftService.capabilities` for docs generated from
the method docstring.

For each successful call to list capabilities, a result dictionary will be
returned with the contents described below:

.. code-block:: python

    {
        'action': 'capabilities',
        'timestamp': <time of the call>,
        'success': True,
        'capabilities': <dictionary containing capability details>
    }

The contents of the capabilities dictionary contain the core swift capabilities
under the key ``swift``; all other keys show the configuration options for
additional middlewares deployed in the proxy pipeline. An example capabilities
dictionary is given below:

.. code-block:: python

    {
        'account_quotas': {},
        'bulk_delete': {
            'max_deletes_per_request': 10000,
            'max_failed_deletes': 1000
        },
        'bulk_upload': {
            'max_containers_per_extraction': 10000,
            'max_failed_extractions': 1000
        },
        'container_quotas': {},
        'container_sync': {'realms': {}},
        'formpost': {},
        'keystoneauth': {},
        'slo': {
            'max_manifest_segments': 1000,
            'max_manifest_size': 2097152,
            'min_segment_size': 1048576
        },
        'swift': {
            'account_autocreate': True,
            'account_listing_limit': 10000,
            'allow_account_management': True,
            'container_listing_limit': 10000,
            'extra_header_count': 0,
            'max_account_name_length': 256,
            'max_container_name_length': 256,
            'max_file_size': 5368709122,
            'max_header_size': 8192,
            'max_meta_count': 90,
            'max_meta_name_length': 128,
            'max_meta_overall_size': 4096,
            'max_meta_value_length': 256,
            'max_object_name_length': 1024,
            'policies': [
                {'default': True, 'name': 'Policy-0'}
            ],
            'strict_cors_mode': False,
            'version': '2.2.2'
        },
        'tempurl': {
            'methods': ['GET', 'HEAD', 'PUT']
        }
    }

.. topic:: Example

   The code below demonstrates the use of ``capabilities`` to determine if the
   Swift cluster supports static large objects, and if so, the maximum number
   of segments that can be described in a single manifest file, along with the
   size restrictions on those objects:

   .. literalinclude:: ../../examples/capabilities.py
      :language: python
