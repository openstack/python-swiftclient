==============================
The swiftclient.Connection API
==============================

A low level API that provides methods for authentication and methods that
correspond to the individual REST API calls described in the swift
documentation.

For usage details see the client docs: :mod:`swiftclient.client`.

Authentication
--------------

This section covers the various combinations of kwargs required when creating
an instance of the ``Connection`` object for communicating with a swift
object store. The combinations of options required for each authentication
version are detailed below, but are
just a subset of those that can be used to successfully authenticate. These
are the most common and recommended combinations.

Keystone Session
~~~~~~~~~~~~~~~~

.. code-block:: python

    from keystoneauth1 import session
    from keystoneauth1.identity import v3

    # Create a password auth plugin
    auth = v3.Password(auth_url='http://127.0.0.1:5000/v3/',
                       username='tester',
                       password='testing',
                       user_domain_name='Default',
                       project_name='Default',
                       project_domain_name='Default')

    # Create session
    keystone_session = session.Session(auth=auth)

    # Create swiftclient Connection
    swift_conn = Connection(session=keystone_session)

Keystone v3
~~~~~~~~~~~

.. code-block:: python

    _authurl = 'http://127.0.0.1:5000/v3/'
    _auth_version = '3'
    _user = 'tester'
    _key = 'testing'
    _os_options = {
        'user_domain_name': 'Default',
        'project_domain_name': 'Default',
        'project_name': 'Default'
    }

    conn = Connection(
        authurl=_authurl,
        user=_user,
        key=_key,
        os_options=_os_options,
        auth_version=_auth_version
    )

Keystone v2
~~~~~~~~~~~

.. code-block:: python

    _authurl = 'http://127.0.0.1:5000/v2.0/'
    _auth_version = '2'
    _user = 'tester'
    _key = 'testing'
    _tenant_name = 'test'

    conn = Connection(
        authurl=_authurl,
        user=_user,
        key=_key,
        tenant_name=_tenant_name,
        auth_version=_auth_version
    )

Legacy Auth
~~~~~~~~~~~

.. code-block:: python

    _authurl = 'http://127.0.0.1:8080/'
    _auth_version = '1'
    _user = 'tester'
    _key = 'testing'
    _tenant_name = 'test'

    conn = Connection(
        authurl=_authurl,
        user=_user,
        key=_key,
        tenant_name=_tenant_name,
        auth_version=_auth_version
    )

Examples
--------

In this section we present some simple code examples that demonstrate the usage
of the ``Connection`` API. You can find full details of the options and methods
available to the ``Connection`` API in the docstring generated documentation:
:mod:`swiftclient.client`.

List the available containers:

.. code-block:: python

    resp_headers, containers = conn.get_account()
    print("Response headers: %s" % resp_headers)
    for container in containers:
        print(container)

Create a new container:

.. code-block:: python

    container = 'new-container'
    conn.put_container(container)
    resp_headers, containers = conn.get_account()
    if container in containers:
        print("The container was created")

Create a new object with the contents of a local text file:

.. code-block:: python

    container = 'new-container'
    with open('local.txt', 'r') as local:
        conn.put_object(
            container,
            'local_object.txt',
            contents=local,
            content_type='text/plain'
        )

Confirm presence of the object:

.. code-block:: python

    obj = 'local_object.txt'
    container = 'new-container'
    try:
        resp_headers = conn.head_object(container, obj)
        print('The object was successfully created')
    except ClientException as e:
        if e.http_status = '404':
            print('The object was not found')
        else:
            print('An error occurred checking for the existence of the object')

Download the created object:

.. code-block:: python

    obj = 'local_object.txt'
    container = 'new-container'
    resp_headers, obj_contents = conn.get_object(container, obj)
    with open('local_copy.txt', 'w') as local:
        local.write(obj_contents)

Delete the created object:

.. code-block:: python

    obj = 'local_object.txt'
    container = 'new-container'
    try:
        conn.delete_object(container, obj)
        print("Successfully deleted the object")
    except ClientException as e:
        print("Failed to delete the object with error: %s" % e)
