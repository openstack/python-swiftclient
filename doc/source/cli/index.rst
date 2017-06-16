====
CLI
====

The ``swift`` tool is a command line utility for communicating with an OpenStack
Object Storage (swift) environment. It allows one to perform several types of
operations.


For help on a specific :command:`swift` command, enter:

.. code-block:: console

   $ swift COMMAND --help

.. _swift_command_usage:

swift usage
~~~~~~~~~~~

.. code-block:: console

   Usage: swift [--version] [--help] [--os-help] [--snet] [--verbose]
                [--debug] [--info] [--quiet] [--auth <auth_url>]
                [--auth-version <auth_version> |
                    --os-identity-api-version <auth_version> ]
                [--user <username>]
                [--key <api_key>] [--retries <num_retries>]
                [--os-username <auth-user-name>] [--os-password <auth-password>]
                [--os-user-id <auth-user-id>]
                [--os-user-domain-id <auth-user-domain-id>]
                [--os-user-domain-name <auth-user-domain-name>]
                [--os-tenant-id <auth-tenant-id>]
                [--os-tenant-name <auth-tenant-name>]
                [--os-project-id <auth-project-id>]
                [--os-project-name <auth-project-name>]
                [--os-project-domain-id <auth-project-domain-id>]
                [--os-project-domain-name <auth-project-domain-name>]
                [--os-auth-url <auth-url>] [--os-auth-token <auth-token>]
                [--os-storage-url <storage-url>] [--os-region-name <region-name>]
                [--os-service-type <service-type>]
                [--os-endpoint-type <endpoint-type>]
                [--os-cacert <ca-certificate>] [--insecure]
                [--os-cert <client-certificate-file>]
                [--os-key <client-certificate-key-file>]
                [--no-ssl-compression]
                <subcommand> [--help] [<subcommand options>]

**Subcommands:**

``delete``
  Delete a container or objects within a container.

``download``
  Download objects from containers.

``list``
  Lists the containers for the account or the objects
  for a container.

``post``
  Updates meta information for the account, container,
  or object; creates containers if not present.

``copy``
  Copies object, optionally adds meta

``stat``
  Displays information for the account, container,
  or object.

``upload``
  Uploads files or directories to the given container.

``capabilities``
  List cluster capabilities.

``tempurl``
  Create a temporary URL.

``auth``
  Display auth related environment variables.

.. _swift_command_options:

swift optional arguments
~~~~~~~~~~~~~~~~~~~~~~~~

``--version``
  show program's version number and exit

``-h, --help``
  show this help message and exit

``--os-help``
  Show OpenStack authentication options.

``-s, --snet``
  Use SERVICENET internal network.

``-v, --verbose``
  Print more info.

``--debug``
  Show the curl commands and results of all http queries
  regardless of result status.

``--info``
  Show the curl commands and results of all http queries
  which return an error.

``-q, --quiet``
  Suppress status output.

``-A AUTH, --auth=AUTH``
  URL for obtaining an auth token.

``-V AUTH_VERSION, --auth-version=AUTH_VERSION, --os-identity-api-version=AUTH_VERSION``
  Specify a version for authentication. Defaults to
  ``env[ST_AUTH_VERSION]``, ``env[OS_AUTH_VERSION]``,
  ``env[OS_IDENTITY_API_VERSION]`` or 1.0.

``-U USER, --user=USER``
  User name for obtaining an auth token.

``-K KEY, --key=KEY``
  Key for obtaining an auth token.

``-R RETRIES, --retries=RETRIES``
  The number of times to retry a failed connection.

``--insecure``
  Allow swiftclient to access servers without having to
  verify the SSL certificate. Defaults to
  ``env[SWIFTCLIENT_INSECURE]`` (set to 'true' to enable).

``--no-ssl-compression``
  This option is deprecated and not used anymore. SSL
  compression should be disabled by default by the
  system SSL library.

Authentication
~~~~~~~~~~~~~~

This section covers the options for authenticating with a swift
object store. The combinations of options required for each authentication
version are detailed below, but are just a subset of those that can be used
to successfully authenticate. These are the most common and recommended
combinations.

You should obtain the details of your authentication version and credentials
from your storage provider. These details should make it clearer which of the
authentication sections below are most likely to allow you to connect to your
storage account.

Keystone v3
-----------

.. code-block:: bash

    swift --os-auth-url https://api.example.com:5000/v3 --auth-version 3 \
          --os-project-name project1 --os-project-domain-name domain1 \
          --os-username user --os-user-domain-name domain1 \
          --os-password password list

    swift --os-auth-url https://api.example.com:5000/v3 --auth-version 3 \
          --os-project-id 0123456789abcdef0123456789abcdef \
          --os-user-id abcdef0123456789abcdef0123456789 \
          --os-password password list

Manually specifying the options above on the command line can be avoided by
setting the following combinations of environment variables:

.. code-block:: bash

    ST_AUTH_VERSION=3
    OS_USERNAME=user
    OS_USER_DOMAIN_NAME=domain1
    OS_PASSWORD=password
    OS_PROJECT_NAME=project1
    OS_PROJECT_DOMAIN_NAME=domain1
    OS_AUTH_URL=https://api.example.com:5000/v3

    ST_AUTH_VERSION=3
    OS_USER_ID=abcdef0123456789abcdef0123456789
    OS_PASSWORD=password
    OS_PROJECT_ID=0123456789abcdef0123456789abcdef
    OS_AUTH_URL=https://api.example.com:5000/v3

Keystone v2
-----------

.. code-block:: bash

    swift --os-auth-url https://api.example.com:5000/v2.0 \
          --os-tenant-name tenant \
          --os-username user --os-password password list

Manually specifying the options above on the command line can be avoided by
setting the following environment variables:

.. code-block:: bash

    ST_AUTH_VERSION=2.0
    OS_USERNAME=user
    OS_PASSWORD=password
    OS_TENANT_NAME=tenant
    OS_AUTH_URL=https://api.example.com:5000/v2.0

Legacy auth systems
-------------------

You can configure swift to work with any number of other authentication systems
that we will not cover in this document. If your storage provider is not using
Keystone to provide access tokens, please contact them for instructions on the
required options. It is likely that the options will need to be specified as
below:

.. code-block:: bash

    swift -A https://api.example.com/v1.0 -U user -K api_key list

Specifying the options above manually on the command line can be avoided by
setting the following environment variables:

.. code-block:: bash

    ST_AUTH_VERSION=1.0
    ST_AUTH=https://api.example.com/v1.0
    ST_USER=user
    ST_KEY=key

It is also possible that you need to use a completely separate auth system, in which
case ``swiftclient`` cannot request a token for you. In this case you should make the
authentication request separately and access your storage using the token and
storage URL options shown below:

.. code-block:: bash

    swift --os-auth-token 6ee5eb33efad4e45ab46806eac010566 \
          --os-storage-url https://10.1.5.2:8080/v1/AUTH_ced809b6a4baea7aeab61a \
          list

.. We need the backslash below in order to indent the note
\

  .. note::

     Leftover environment variables are a common source of confusion when
     authorization fails.

CLI commands
~~~~~~~~~~~~

.. _swift_auth:

Auth
----

.. code-block:: console

   Usage: swift auth

Display authentication variables in shell friendly format. Command to run to export storage
URL and auth token into ``OS_STORAGE_URL`` and ``OS_AUTH_TOKEN``: ``swift auth``.
Command to append to a runcom file (e.g. ``~/.bashrc``, ``/etc/profile``) for automatic
authentication: ``swift auth -v -U test:tester -K testing``.

.. _swift_stat:

swift stat
----------

.. code-block:: console

   Usage: swift stat [--lh] [--header <header:value>]
                     [<container> [<object>]]

Displays information for the account, container, or object depending on
the arguments given (if any). In verbose mode, the storage URL and the
authentication token are displayed as well.

**Positional arguments:**

``[container]``
  Name of container to stat from.

``[object]``
  Name of object to stat.

**Optional arguments:**

``--lh``
  Report sizes in human readable format similar to
  ls -lh.

``-H, --header <header:value>``
  Adds a custom request header to use for stat.

.. _swift_list:

swift list
----------

.. code-block:: console

   Usage: swift list [--long] [--lh] [--totals] [--prefix <prefix>]
                     [--delimiter <delimiter>] [--header <header:value>]
                     [<container>]

Lists the containers for the account or the objects for a container.
The ``-p <prefix>`` or ``--prefix <prefix>`` is an option that will only
list items beginning with that prefix. The ``-d <delimiter>`` or
``--delimiter <delimiter>`` is an option (for container listings only)
that will roll up items with the given delimiter (see `OpenStack Swift
general documentation <http://docs.openstack.org/swift/latest/>` for
what this means).

The ``-l`` and ``--lh`` options provide more detail, similar to ``ls -l``
and ``ls -lh``, the latter providing sizes in human readable format
(For example: ``3K``, ``12M``, etc). The latter two switches use more
overhead to retrieve the displayed details, which is directly proportional
to the number of container or objects listed.

**Positional arguments:**

``[container]``
  Name of container to list object in.

**Optional arguments:**

``-l, --long``
  Long listing format, similar to ls -l.

``--lh``
  Report sizes in human readable format similar to
  ls -lh.

``-t, --totals``
  Used with -l or --lh, only report totals.

``-p <prefix>, --prefix <prefix>``
  Only list items beginning with the prefix.

``-d <delim>, --delimiter <delim>``
  Roll up items with the given delimiter. For containers
  only. See OpenStack Swift API documentation for what
  this means.

``-H, --header <header:value>``
  Adds a custom request header to use for listing.

.. _swift_upload:

swift upload
------------

.. code-block:: console

   Usage: swift upload [--changed] [--skip-identical] [--segment-size <size>]
                       [--segment-container <container>] [--leave-segments]
                       [--object-threads <thread>] [--segment-threads <threads>]
                       [--header <header>] [--use-slo] [--ignore-checksum]
                       [--object-name <object-name>]
                       <container> <file_or_directory> [<file_or_directory>] [...]

Uploads the files and directories specified by the remaining arguments to the
given container. The ``-c`` or ``--changed`` is an option that will only
upload files that have changed since the last upload. The
``--object-name <object-name>`` is an option that will upload a file and
name object to ``<object-name>`` or upload a directory and use ``<object-name>``
as object prefix. If the file name is "-", client reads content from standard
input. In this case ``--object-name`` is required to set the name of the object
and no other files may be given.  The ``-S <size>`` or ``--segment-size <size>``
and ``--leave-segments`` are options as well (see ``--help`` for more).

**Positional arguments:**

``<container>``
  Name of container to upload to.

``<file_or_directory>``
  Name of file or directory to upload. Specify multiple
  times for multiple uploads.

**Optional arguments:**

``-c, --changed``
  Only upload files that have changed since the last
  upload.

``--skip-identical``
  Skip uploading files that are identical on both sides.

``-S, --segment-size <size>``
  Upload files in segments no larger than <size> (in
  Bytes) and then create a "manifest" file that will
  download all the segments as if it were the original
  file.

``--segment-container <container>``
  Upload the segments into the specified container. If
  not specified, the segments will be uploaded to a
  <container>_segments container to not pollute the
  main <container> listings.

``--leave-segments``
  Indicates that you want the older segments of manifest
  objects left alone (in the case of overwrites).

``--object-threads <threads>``
  Number of threads to use for uploading full objects.
  Default is 10.

``--segment-threads <threads>``
  Number of threads to use for uploading object segments.
  Default is 10.

``-H, --header <header:value>``
  Adds a customized request header. This option may be
  repeated. Example: -H "content-type:text/plain"
  -H "Content-Length: 4000".

``--use-slo``
  When used in conjunction with --segment-size it will
  create a Static Large Object instead of the default
  Dynamic Large Object.

``--object-name <object-name>``
  Upload file and name object to <object-name> or upload
  dir and use <object-name> as object prefix instead of
  folder name.

``--ignore-checksum``
  Turn off checksum validation for uploads.


.. _swift_post:

swift post
----------

.. code-block:: console

   Usage: swift post [--read-acl <acl>] [--write-acl <acl>] [--sync-to]
                     [--sync-key <sync-key>] [--meta <name:value>]
                     [--header <header>]
                     [<container> [<object>]]

Updates meta information for the account, container, or object depending
on the arguments given. If the container is not found, the ``swiftclient``
will create it automatically, but this is not true for accounts and
objects. Containers also allow the ``-r <read-acl>`` (or ``--read-acl
<read-acl>``) and ``-w <write-acl>`` (or ``--write-acl <write-acl>``) options.
The ``-m`` or ``--meta`` option is allowed on accounts, containers and objects,
and is used to define the user metadata items to set in the form ``Name:Value``.
You can repeat this option. For example: ``post -m Color:Blue -m Size:Large``

For more information about ACL formats see the documentation:
`ACLs <http://docs.openstack.org/swift/latest/misc.html#acls>`_.

**Positional arguments:**

``[container]``
  Name of container to post to.

``[object]``
  Name of object to post.

**Optional arguments:**

``-r, --read-acl <acl>``
  Read ACL for containers. Quick summary of ACL syntax:
  ``.r:*``, ``.r:-.example.com``, ``.r:www.example.com``,
  ``account1`` (v1.0 identity API only),
  ``account1:*``, ``account2:user2`` (v2.0+ identity API).

``-w, --write-acl <acl>``
  Write ACL for containers. Quick summary of ACL syntax:
  ``account1`` (v1.0 identity API only),
  ``account1:*``, ``account2:user2`` (v2.0+ identity API).

``-t, --sync-to <sync-to>``
  Sync To for containers, for multi-cluster replication.

``-k, --sync-key <sync-key>``
  Sync Key for containers, for multi-cluster replication.

``-m, --meta <name:value>``
  Sets a meta data item. This option may be repeated.

  Example: -m Color:Blue -m Size:Large

``-H, --header <header:value>``
  Adds a customized request header.
  This option may be repeated.

  Example: -H "content-type:text/plain" -H "Content-Length: 4000"

.. _swift_download:

swift download
--------------

.. code-block:: console

   Usage: swift download [--all] [--marker <marker>] [--prefix <prefix>]
                         [--output <out_file>] [--output-dir <out_directory>]
                         [--object-threads <threads>] [--ignore-checksum]
                         [--container-threads <threads>] [--no-download]
                         [--skip-identical] [--remove-prefix]
                         [--header <header:value>] [--no-shuffle]
                         [<container> [<object>] [...]]

Downloads everything in the account (with ``--all``), or everything in a
container, or a list of objects depending on the arguments given. For a
single object download, you may use the ``-o <filename>`` or ``--output <filename>``
option to redirect the output to a specific file or ``-`` to
redirect to stdout. The ``--ignore-checksum`` is an option that turn off
checksum validation. You can specify optional headers with the repeatable
cURL-like option ``-H [--header <name:value>]``. ``--ignore-mtime`` ignores the
``x-object-meta-mtime`` metadata entry on the object (if present) and instead
creates the downloaded files with fresh atime and mtime values.

**Positional arguments:**

``<container>``
  Name of container to download from. To download a
  whole account, omit this and specify --all.

``<object>``
  Name of object to download. Specify multiple times
  for multiple objects. Omit this to download all
  objects from the container.

**Optional arguments:**

``-a, --all``
  Indicates that you really want to download
  everything in the account.

``-m, --marker <marker>``
  Marker to use when starting a container or account
  download.

``-p, --prefix <prefix>``
  Only download items beginning with <prefix>

``-r, --remove-prefix``
  An optional flag for --prefix <prefix>, use this
  option to download items without <prefix>

``-o, --output <out_file>``
  For a single file download, stream the output to
  <out_file>. Specifying "-" as <out_file> will
  redirect to stdout.

``-D, --output-dir <out_directory>``
  An optional directory to which to store objects.
  By default, all objects are recreated in the current
  directory.

``--object-threads <threads>``
  Number of threads to use for downloading objects.
  Default is 10.

``--container-threads <threads>``
  Number of threads to use for downloading containers.
  Default is 10.

``--no-download``
  Perform download(s), but don't actually write anything
  to disk.

``-H, --header <header:value>``
  Adds a customized request header to the query, like
  "Range" or "If-Match". This option may be repeated.

  Example: --header "content-type:text/plain"

``--skip-identical``
  Skip downloading files that are identical on both
  sides.

``--ignore-checksum``
  Turn off checksum validation for downloads.

``--no-shuffle``
  By default, when downloading a complete account or
  container, download order is randomised in order to
  reduce the load on individual drives when multiple
  clients are executed simultaneously to download the
  same set of objects (e.g. a nightly automated download
  script to multiple servers). Enable this option to
  submit download jobs to the thread pool in the order
  they are listed in the object store.

.. _swift_delete:

swift delete
------------

.. code-block:: console

   Usage: swift delete [--all] [--leave-segments]
                       [--object-threads <threads>]
                       [--container-threads <threads>]
                       [--header <header:value>]
                       [<container> [<object>] [...]]

Deletes everything in the account (with ``--all``), or everything in a
container, or a list of objects depending on the arguments given. Segments
of manifest objects will be deleted as well, unless you specify the
``--leave-segments`` option.

**Positional arguments:**

``[<container>]``
  Name of container to delete from.

``[<object>]``
  Name of object to delete. Specify multiple times
  for multiple objects.

**Optional arguments:**

``-a, --all``
  Delete all containers and objects.

``--leave-segments``
  Do not delete segments of manifest objects.

``-H, --header <header:value>``
  Adds a custom request header to use for deleting
  objects or an entire container.


``--object-threads <threads>``
  Number of threads to use for deleting objects.
  Default is 10.

``--container-threads <threads>``
  Number of threads to use for deleting containers.
  Default is 10.

.. _swift_copy:

swift copy
----------

.. code-block:: console

   Usage: swift copy [--destination </container/object>] [--fresh-metadata]
                     [--meta <name:value>] [--header <header>] <container>
                     <object> [<object>] [...]

Copies an object to a new destination or adds user metadata to an object. Depending
on the options supplied, you can preserve existing metadata in contrast to the post
command. The ``--destination`` option sets the copy target destination in the form
``/container/object``. If not set, the object will be copied onto itself which is useful
for adding metadata. You can use the ``-M`` or ``--fresh-metadata`` option to copy
an object without existing user meta data, and the ``-m`` or ``--meta`` option
to define user meta data items to set in the form ``Name:Value``. You can repeat
this option. For example: ``copy -m Color:Blue -m Size:Large``.

**Positional arguments:**

``<container>``
  Name of container to copy from.

``<object>``
  Name of object to copy. Specify multiple times for multiple objects

**Optional arguments:**

``-d, --destination </container[/object]>``
  The container and name of the destination object. Name
  of destination object can be omitted, then will be
  same as name of source object. Supplying multiple
  objects and destination with object name is invalid.

``-M, --fresh-metadata``
  Copy the object without any existing metadata,
  If not set, metadata will be preserved or appended

``-m, --meta <name:value>``
  Sets a meta data item. This option may be repeated.

  Example: -m Color:Blue -m Size:Large

``-H, --header <header:value>``
  Adds a customized request header. This option may be repeated.

  Example: -H "content-type:text/plain" -H "Content-Length: 4000"

.. _swift_capabilities:

swift capabilities
------------------

.. code-block:: console

   Usage: swift capabilities [--json] [<proxy_url>]

Displays cluster capabilities. The output includes the list of the
activated Swift middlewares as well as relevant options for each ones.
Additionally the command displays relevant options for the Swift core. If
the ``proxy-url`` option is not provided, the storage URL retrieved after
authentication is used as ``proxy-url``.

**Optional positional arguments:**

``<proxy_url>``
  Proxy URL of the cluster to retrieve capabilities.

``--json``
  Print the cluster capabilities in JSON format.

.. _swift_tempurl:

swift tempurl
-------------

.. code-block:: console

   Usage: swift tempurl [--absolute] [--prefix-based]
                        <method> <seconds> <path> <key>

Generates a temporary URL for a Swift object. ``method`` option sets an HTTP method to
allow for this temporary URL that is usually ``GET`` or ``PUT``. ``time`` option sets
the amount of time the temporary URL will be valid for.
``time`` can be specified as an integer, denoting the number of seconds
from now on until the URL shall be valid; or, if ``--absolute``
is passed, the Unix timestamp when the temporary URL will expire.
But beyond that, ``time`` can also be specified as an ISO 8601 timestamp
in one of following formats:

    i) Complete date: YYYY-MM-DD (eg 1997-07-16)

    ii) Complete date plus hours, minutes and seconds:
        YYYY-MM-DDThh:mm:ss
        (eg 1997-07-16T19:20:30)

    iii) Complete date plus hours, minutes and seconds with UTC designator:
        YYYY-MM-DDThh:mm:ssZ
        (eg 1997-07-16T19:20:30Z)

Please be aware that if you don't provide the UTC designator (i.e., Z)
the timestamp is generated using your local timezone. If only a date is
specified, the time part used will equal to ``00:00:00``.

``path`` option sets the full path to the Swift object.
Example: ``/v1/AUTH_account/c/o``. ``key`` option is
the secret temporary URL key set on the Swift cluster. To set a key, run
``swift post -m "Temp-URL-Key: <your secret key>"``. To generate a prefix-based temporary
URL use the ``--prefix-based`` option. This URL will contain the path to the prefix. Do not
forget to append the desired objectname at the end of the path portion (and before the
query portion) before sharing the URL. It is possible to use ISO 8601 UTC timestamps within the
URL by using the ``--iso8601`` option.

**Positional arguments:**

``<method>``
  An HTTP method to allow for this temporary URL.
  Usually 'GET' or 'PUT'.

``<seconds>``
  The amount of time in seconds the temporary URL will be
  valid for; or, if --absolute is passed, the Unix
  timestamp when the temporary URL will expire.

``<path>``
  The full path to the Swift object.

  Example: /v1/AUTH_account/c/o
  or: http://saio:8080/v1/AUTH_account/c/o

``<key>``
  The secret temporary URL key set on the Swift cluster.
  To set a key, run 'swift post -m
  "Temp-URL-Key:b3968d0207b54ece87cccc06515a89d4"'

**Optional arguments:**

``--absolute``
  Interpret the <seconds> positional argument as a Unix
  timestamp rather than a number of seconds in the
  future.

``--prefix-based``
  If present, a prefix-based tempURL will be generated.

Examples
~~~~~~~~

In this section we present some example usage of the ``swift`` CLI. To keep the
examples as short as possible, these examples assume that the relevant authentication
options have been set using environment variables. You can obtain the full list of
commands and options available in the ``swift`` CLI by executing the following:

.. code-block:: bash

    > swift --help
    > swift <command> --help

Simple examples
---------------

List the existing swift containers:

.. code-block:: bash

    > swift list

    container_1

Create a new container:

.. code-block:: bash

    > swift post TestContainer

Upload an object into a container:

.. code-block:: bash

    > swift upload TestContainer testSwift.txt

    testSwift.txt

List the contents of a container:

.. code-block:: bash

    > swift list TestContainer

    testSwift.txt

Copy an object to new destination:

.. code-block:: bash

    > swift copy -d /DestContainer/testSwift.txt SourceContainer testSwift.txt

    SourceContainer/testSwift.txt copied to /DestContainer/testSwift.txt

Delete an object from a container:

.. code-block:: bash

    > swift delete TestContainer testSwift.txt

    testSwift.txt

Delete a container:

.. code-block:: bash

    > swift delete TestContainer

    TestContainer

Display auth related authentication variables in shell friendly format:

.. code-block:: bash

    > swift auth

    export OS_STORAGE_URL=http://127.0.0.1:8080/v1/AUTH_bf5e63572f7a420a83fcf0aa8c72c2c7
    export OS_AUTH_TOKEN=c597015ae19943a18438b52ef3762e79

Download an object from a container:

.. code-block:: bash

    > swift download TestContainer testSwift.txt

    testSwift.txt [auth 0.028s, headers 0.045s, total 0.045s, 0.002 MB/s]

.. We need the backslash below in order to indent the note
\

  .. note::

     To upload an object to a container, your current working directory must be
     where the file is located or you must provide the complete path to the file.
     In other words, the --object-name <object-name> is an option that will upload
     file and name object to <object-name> or upload directory and use <object-name> as
     object prefix. In the case that you provide the complete path of the file,
     that complete path will be the name of the uploaded object.

For example:

.. code-block:: bash

    > swift upload TestContainer /home/swift/testSwift/testSwift.txt

    home/swift/testSwift/testSwift.txt

    > swift list TestContainer

    home/swift/testSwift/testSwift.txt

More complex examples
---------------------

Swift has a single object size limit of 5GiB. In order to upload files larger
than this, we must create a large object that consists of smaller segments.
The example below shows how to upload a large video file as a static large
object in 1GiB segments:

.. code-block:: bash

    > swift upload videos --use-slo --segment-size 1G myvideo.mp4

    myvideo.mp4 segment 8
    myvideo.mp4 segment 4
    myvideo.mp4 segment 2
    myvideo.mp4 segment 7
    myvideo.mp4 segment 0
    myvideo.mp4 segment 1
    myvideo.mp4 segment 3
    myvideo.mp4 segment 6
    myvideo.mp4 segment 5
    myvideo.mp4

This command will upload segments to a container named ``videos_segments``, and
create a manifest file describing the entire object in the ``videos`` container.
For more information on large objects, see the documentation `here
<https://docs.openstack.org/swift/latest/overview_large_objects.html>`_.

.. code-block:: bash

    > swift list videos

    myvideo.mp4

    > swift list videos_segments

    myvideo.mp4/slo/1460229233.679546/9341553868/1073741824/00000000
    myvideo.mp4/slo/1460229233.679546/9341553868/1073741824/00000001
    myvideo.mp4/slo/1460229233.679546/9341553868/1073741824/00000002
    myvideo.mp4/slo/1460229233.679546/9341553868/1073741824/00000003
    myvideo.mp4/slo/1460229233.679546/9341553868/1073741824/00000004
    myvideo.mp4/slo/1460229233.679546/9341553868/1073741824/00000005
    myvideo.mp4/slo/1460229233.679546/9341553868/1073741824/00000006
    myvideo.mp4/slo/1460229233.679546/9341553868/1073741824/00000007
    myvideo.mp4/slo/1460229233.679546/9341553868/1073741824/00000008

Firstly, the key should be set, then generate a temporary URL for a Swift object:

.. code-block:: bash

    > swift post -m "Temp-URL-Key:b3968d0207b54ece87cccc06515a89d4"

    > swift tempurl GET 6000 /v1/AUTH_bf5e63572f7a420a83fcf0aa8c72c2c7\
      /firstcontainer/clean.sh b3968d0207b54ece87cccc06515a89d4

    /v1/AUTH_/firstcontainer/clean.sh?temp_url_sig=\
    9218fc288cc09e5edd857b6a3d43cf2122b906dc&temp_url_expires=1472203614
