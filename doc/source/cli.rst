====
CLI
====

The ``swift`` tool is a command line utility for communicating with an OpenStack
Object Storage (swift) environment. It allows one to perform several types of
operations.

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

    swift -A https://auth.api.rackspacecloud.com/v1.0 -U user -K api_key list

Specifying the options above manually on the command line can be avoided by
setting the following environment variables:

.. code-block:: bash

    ST_AUTH_VERSION=1.0
    ST_AUTH=https://auth.api.rackspacecloud.com/v1.0
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

Stat
----

    ``stat [container [object]]``

       Displays information for the account, container, or object depending on
       the arguments given (if any). In verbose mode, the storage URL and the
       authentication token are displayed as well.

List
----

    ``list [command-options] [container]``

       Lists the containers for the account or the objects for a container.
       The ``-p <prefix>`` or ``--prefix <prefix>`` is an option that will only
       list items beginning with that prefix. The ``-d <delimiter>`` or
       ``--delimiter <delimiter>`` is an option (for container listings only)
       that will roll up items with the given delimiter (see `OpenStack Swift
       general documentation <http://docs.openstack.org/developer/swift/>` for
       what this means).

       The ``-l`` and ``--lh`` options provide more detail, similar to ``ls -l``
       and ``ls -lh``, the latter providing sizes in human readable format
       (For example: ``3K``, ``12M``, etc). The latter two switches use more
       overhead to retrieve the displayed details, which is directly proportional
       to the number of container or objects listed.

Upload
------

    ``upload [command-options] container file_or_directory [file_or_directory] [...]``

       Uploads the files and directories specified by the remaining arguments to the
       given container. The ``-c`` or ``--changed`` is an option that will only
       upload files that have changed since the last upload. The
       ``--object-name <object-name>`` is an option that will upload a file and
       name object to ``<object-name>`` or upload a directory and use ``<object-name>``
       as object prefix. The ``-S <size>`` or ``--segment-size <size>`` and
       ``--leave-segments`` are options as well (see ``--help`` for more).

Post
----

    ``post [command-options] [container] [object]``

       Updates meta information for the account, container, or object depending
       on the arguments given. If the container is not found, the ``swiftclient``
       will create it automatically, but this is not true for accounts and
       objects. Containers also allow the ``-r <read-acl>`` (or ``--read-acl
       <read-acl>``) and ``-w <write-acl>`` (or ``--write-acl <write-acl>``) options.
       The ``-m`` or ``--meta`` option is allowed on accounts, containers and objects,
       and is used to define the user metadata items to set in the form ``Name:Value``.
       You can repeat this option. For example: ``post -m Color:Blue -m Size:Large``

       For more information about ACL formats see the documentation:
       `ACLs <http://docs.openstack.org/developer/swift/misc.html#acls/>`_.

Download
--------

    ``download [command-options] [container] [object] [object] [...]``

       Downloads everything in the account (with ``--all``), or everything in a
       container, or a list of objects depending on the arguments given. For a
       single object download, you may use the ``-o <filename>`` or ``--output <filename>``
       option to redirect the output to a specific file or ``-`` to
       redirect to stdout. The ``--ignore-checksum`` is an option that turn off
       checksum validation. You can specify optional headers with the repeatable
       cURL-like option ``-H [--header <name:value>]``.

Delete
------

    ``delete [command-options] [container] [object] [object] [...]``

       Deletes everything in the account (with ``--all``), or everything in a
       container, or a list of objects depending on the arguments given. Segments
       of manifest objects will be deleted as well, unless you specify the
       ``--leave-segments`` option.

Copy
----

    ``copy [command-options] container object``

       Copies an object to a new destination or adds user metadata to an object. Depending
       on the options supplied, you can preserve existing metadata in contrast to the post
       command. The ``--destination`` option sets the copy target destination in the form
       ``/container/object``. If not set, the object will be copied onto itself which is useful
       for adding metadata. You can use the ``-M`` or ``--fresh-metadata`` option to copy
       an object without existing user meta data, and the ``-m`` or ``--meta`` option
       to define user meta data items to set in the form ``Name:Value``. You can repeat
       this option. For example: ``copy -m Color:Blue -m Size:Large``.

Capabilities
------------

    ``capabilities [proxy-url]``

       Displays cluster capabilities. The output includes the list of the
       activated Swift middlewares as well as relevant options for each ones.
       Additionally the command displays relevant options for the Swift core. If
       the ``proxy-url`` option is not provided, the storage URL retrieved after
       authentication is used as ``proxy-url``.

Tempurl
-------

    ``tempurl [command-options] [method] [seconds] [path] [key]``

       Generates a temporary URL for a Swift object. ``method`` option sets an HTTP method to
       allow for this temporary URL that is usually 'GET' or 'PUT'. ``seconds`` option sets
       the amount of time in seconds the temporary URL will be valid for; or, if ``--absolute``
       is passed, the Unix timestamp when the temporary URL will expire. ``path`` option sets
       the full path to the Swift object. Example: ``/v1/AUTH_account/c/o``. ``key`` option is
       the secret temporary URL key set on the Swift cluster. To set a key, run
       ``swift post -m "Temp-URL-Key: <your secret key>"``. To generate a prefix-based temporary
       URL use the ``--prefix-based`` option. This URL will contain the path to the prefix. Do not
       forget to append the desired objectname at the end of the path portion (and before the
       query portion) before sharing the URL.

Auth
----

    ``auth``

       Display authentication variables in shell friendly format. Command to run to export storage
       URL and auth token into ``OS_STORAGE_URL`` and ``OS_AUTH_TOKEN``: ``swift auth``.
       Command to append to a runcom file (e.g. ``~/.bashrc``, ``/etc/profile``) for automatic
       authentication: ``swift auth -v -U test:tester -K testing``.

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
<http://docs.openstack.org/developer/swift/overview_large_objects.html>`_.

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
