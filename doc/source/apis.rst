======================
python-swiftclient API
======================

The python-swiftclient includes two levels of API. A low level client API that
provides simple python wrappers around the various authentication mechanisms,
the individual HTTP requests, and a high level service API that provides
methods for performing common operations in parallel on a thread pool.

This document aims to provide guidance for choosing between these APIs and
examples of usage for the service API.


Important Considerations
~~~~~~~~~~~~~~~~~~~~~~~~

This section covers some important considerations, helpful hints, and things
to avoid when integrating an object store into your workflow.

An Object Store is not a filesystem
-----------------------------------

.. important::

   It cannot be stressed enough that your usage of the object store should reflect
   the use case, and not treat the storage like a filesystem.

There are 2 main restrictions to bear in mind here when designing your use of the object
store:

#. Objects cannot be renamed due to the way in which objects are stored and
   references by the object store. This usually requires multiple copies of
   the data to be moved between physical storage devices.
   As a result, a move operation is not provided. If the user wants to move an
   object they must re-upload to the new location and delete the
   original.
#. Objects cannot be modified. Objects are stored in multiple locations and are
   checked for integrity based on the ``MD5 sum`` calculated during upload.
   Object creation is a 1-shot event, and in order to modify the contents of an
   object the entire new contents must be re-uploaded. In certain special cases
   it is possible to work around this restriction using large objects, but no
   general file-like access is available to modify a stored object.


The swiftclient.Connection API
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A low level API that provides methods for authentication and methods that
correspond to the individual REST API calls described in the swift
documentation.

For usage details see the client docs: :mod:`swiftclient.client`.


The swiftclient.SwiftService API
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A higher level API aimed at allowing developers an easy way to perform multiple
operations asynchronously using a configurable thread pool. Documentation for each
service method call can be found here: :mod:`swiftclient.service`.

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
^^^^^^^

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

    ``shuffle``: ``False``
        When downloading objects, the default behaviour of the CLI is to shuffle
        lists of objects in order to spread the load on storage drives when multiple
        clients are downloading the same files to multiple locations (e.g. in the
        event of distributing an update). When using the ``SwiftService`` directly,
        object downloads are scheduled in the same order as they appear in the container
        listing. When combined with a single download thread this means that objects
        are downloaded in lexically-sorted order. Setting this option to ``True``
        gives the same shuffling behaviour as the CLI.

Other available options can be found in ``swiftclient/service.py`` in the
source code for ``python-swiftclient``. Each ``SwiftService`` method also allows
for an optional dictionary to override those specified at init time, and the
appropriate docstrings show which options modify each method's behaviour.

Authentication
~~~~~~~~~~~~~~

This section covers the various options for authenticating with a swift
object store. The combinations of options required for each authentication
version are detailed below.

Version 1.0 Auth
----------------

    ``auth_version``: ``environ.get('ST_AUTH_VERSION')``

    ``auth``: ``environ.get('ST_AUTH')``

    ``user``: ``environ.get('ST_USER')``

    ``key``: ``environ.get('ST_KEY')``


Version 2.0 and 3.0 Auth
------------------------

    ``auth_version``: ``environ.get('ST_AUTH_VERSION')``

    ``os_username``: ``environ.get('OS_USERNAME')``

    ``os_password``: ``environ.get('OS_PASSWORD')``

    ``os_tenant_name``: ``environ.get('OS_TENANT_NAME')``

    ``os_auth_url``: ``environ.get('OS_AUTH_URL')``

As is evident from the default values, if these options are not set explicitly
in the options dictionary, then they will default to the values of the given
environment variables. The ``SwiftService`` authentication automatically selects
the auth version based on the combination of options specified, but
having options from different auth versions can cause unexpected behaviour.

  .. note::

     Leftover environment variables are a common source of confusion when
     authorization fails.

Operation Return Values
~~~~~~~~~~~~~~~~~~~~~~~

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
   of the given objects in the the given container (through the returned
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

Example
-------

The code below demonstrates the use of ``stat`` to retrieve the headers for a
given list of objects in a container using 20 threads. The code creates a
mapping from object name to headers.

.. code-block:: python

    import logging

    from swiftclient.service import SwiftService

    logger = logging.getLogger()
    _opts = {'object_dd_threads': 20}
    with SwiftService(options=_opts) as swift:
        container = 'container1'
        objects = [ 'object_%s' % n for n in range(0,100) ]
        header_data = {}
        stats_it = swift.stat(container=container, objects=objects)
        for stat_res in stats_it:
            if stat_res['success']:
                header_data[stat_res['object']] = stat_res['headers']
            else:
                logger.error(
                    'Failed to retrieve stats for %s' % stat_res['object']
                )

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

Example
-------

The code below demonstrates the use of ``list`` to list all items in a
container that are over 10MiB in size:

.. code-block:: python

    container = 'example_container'
    minimum_size = 10*1024**2
    with SwiftService() as swift:
        try:
            stats_parts_gen = swift.list(container=container)
            for stats in stats_parts_gen:
                if stats["success"]:
                    for item in stats["listing"]:
                        i_size = int(item["bytes"])
                        if i_size > minimum_size:
                            i_name = item["name"]
                            i_etag = item["hash"]
                            print(
                                "%s [size: %s] [etag: %s]" %
                                (i_name, i_size, i_etag)
                            )
                else:
                    raise stats["error"]
        except SwiftError as e:
            output_manager.error(e.value)

Post
~~~~

Post can be called against an account, container or list of objects in order to
update the metadata attached to the given items. Each element of the object list
may be a plain string of the object name, or a ``SwiftPostObject`` that
allows finer control over the options applied to each of the individual post
operations. In the first two cases a single dictionary is returned containing the
results of the operation, and in the case of a list of objects being supplied,
an iterator over the results generated for each object post is returned. If the
given container or account does not exist, the ``post`` method will raise a
``SwiftError``.

.. When a string is given for the object name, the options

Successful metadata update results are dictionaries as described below:

.. code-block:: python

    {
        'action': <'post_account'|<'post_container'>|'post_object'>,
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



.. Example
.. -------

.. TBD

.. Download
.. ~~~~~~~~

.. TBD

.. Example
.. -------

.. TBD

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
granularity of invidivual files.

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

Example
-------

The code below demonstrates the use of ``upload`` to upload all files and
folders in ``/tmp``, and renaming each object by replacing ``/tmp`` in the
object or directory marker names with ``temporary-objects``:

.. code-block:: python

    _opts['object_uu_threads'] = 20
    with SwiftService(options=_opts) as swift, OutputManager() as out_manager:
        try:
            # Collect all the files and folders in '/tmp'
            objs = []
            dir_markers = []
            dir = '/tmp':
                for (_dir, _ds, _fs) in walk(f):
                    if not (_ds + _fs):
                        dir_markers.append(_dir)
                    else:
                        objs.extend([join(_dir, _f) for _f in _fs])

            # Now that we've collected all the required files and dir markers
            # build the ``SwiftUploadObject``s for the call to upload
            objs = [
                SwiftUploadObject(
                    o, object_name=o.replace(
                        '/tmp', 'temporary-objects', 1
                    )
                ) for o in objs
            ]
            dir_markers = [
                SwiftUploadObject(
                    None, object_name=d.replace(
                        '/tmp', 'temporary-objects', 1
                    ), options={'dir_marker': True}
                ) for d in dir_markers
            ]

            # Schedule uploads on the SwiftService thread pool and iterate
            # over the results
            for r in swift.upload(container, objs + dir_markers):
                if r['success']:
                    if 'object' in r:
                        out_manager.print_msg(r['object'])
                    elif 'for_object' in r:
                        out_manager.print_msg(
                            '%s segment %s' % (r['for_object'],
                                               r['segment_index'])
                            )
                else:
                    error = r['error']
                    if r['action'] == "create_container":
                        out_manager.warning(
                            'Warning: failed to create container '
                            "'%s'%s", container, msg
                        )
                    elif r['action'] == "upload_object":
                        out_manager.error(
                            "Failed to upload object %s to container %s: %s" %
                            (container, r['object'], error)
                        )
                    else:
                        out_manager.error("%s" % error)

        except SwiftError as e:
            out_manager.error(e.value)

.. Delete
.. ~~~~~~
.. Do we want to hide this section until it is complete?

.. TBD

.. Example
.. -------

.. Do we want to hide this section until it is complete?

.. TBD

.. Capabilities
.. ~~~~~~~~~~~~

.. Do we want to hide this section until it is complete?

.. TBD

.. Example
.. -------

.. Do we want to hide this section until it is complete?

.. TBD

