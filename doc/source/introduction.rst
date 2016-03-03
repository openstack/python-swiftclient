============
Introduction
============

Where to Start?
~~~~~~~~~~~~~~~

The ``python-swiftclient`` project comprises a command line tool and two
separate APIs for accessing swift programmatically. Choosing the most
appropriate method for a given use case is the first problem a user needs to
solve.

Use Cases
---------

Alongside the command line tool, the ``python-swiftclient`` includes two
levels of API:

 * A low level client API that provides simple Python wrappers around the
   various authentication mechanisms and the individual HTTP requests.
 * A high level service API that provides methods for performing common
   operations in parallel on a thread pool.

Example use cases:

  * Uploading and retrieving data
      Use the command line tool if you are simply uploading and downloading
      files and directories to and from your filesystem. The command line tool
      can be integrated into a shell script to automate tasks.

  * Integrating into an automated Python workflow
      Use the ``SwiftService`` API to perform operations offered by the CLI
      if your use case requires integration with a Python-based workflow.
      This method offers greater control and flexibility over individual object
      operations, such as the metadata set on each object. The ``SwiftService``
      class provides methods to perform multiple sets of operations against a
      swift object store using a configurable shared thread pool. A single
      instance of the ``SwiftService`` class can be shared between multiple
      threads in your own code.

  * Developing an application in Python to access a swift object store
      Use the ``SwiftService`` API to develop Python applications that use
      swift to store and retrieve objects. A ``SwiftService`` instance provides
      a configurable thread pool for performing all operations supported by the
      CLI.

  * Fine-grained control over threading or the requests being performed
      Use the ``Connection`` API if your use case requires fine grained control
      over advanced features or you wish to use your own existing threading
      model. Examples of advanced features requiring the use of the
      ``Connection`` API include creating an SLO manifest that references
      already existing objects, or fine grained control over the query strings
      supplied with each HTTP request.

Important considerations
~~~~~~~~~~~~~~~~~~~~~~~~

This section covers some important considerations, helpful hints, and things to
avoid when integrating an object store into your workflow.

An object store is not a filesystem
-----------------------------------

It cannot be stressed enough that your usage of the object store should reflect
the proper use case, and not treat the storage like a traditional filesystem.
There are two main restrictions to bear in mind when designing an application
that uses an object store:

    * You cannot rename objects. Due to fact that the name of an object is one
      of the factors that determines where the object and its replicas are stored,
      renaming would require multiple copies of the data to be moved between
      physical storage devices. If you want to rename an object you must upload
      to the new location, or make a server side copy request to the new location,
      and then delete the original.

    * You cannot modify objects. Objects are stored in multiple locations and
      are checked for integrity based on the MD5 sum calculated during
      upload. In order to modify the contents of an object, the entire desired
      contents must be re-uploaded. In certain special cases it is possible to
      work around this restriction using large objects, but no general
      file-like access is available to modify a stored object.

Objects cannot be locked
------------------------

There is no mechanism to perform a combination of reading the
data/metadata from an object and writing an update to that data/metadata in an
atomic way. Any user with access to a container could update the contents or
metadata associated with an object at any time.

Workflows that assume that no updates have been made since the last read of an
object should be discouraged. Enabling a workflow of this type requires an
external object locking mechanism and/or cooperation between all clients
accessing the data.
