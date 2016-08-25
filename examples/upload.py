import logging

from os import walk
from os.path import join
from swiftclient.multithreading import OutputManager
from swiftclient.service import SwiftError, SwiftService, SwiftUploadObject
from sys import argv

logging.basicConfig(level=logging.ERROR)
logging.getLogger("requests").setLevel(logging.CRITICAL)
logging.getLogger("swiftclient").setLevel(logging.CRITICAL)
logger = logging.getLogger(__name__)

_opts = {'object_uu_threads': 20}
dir = argv[1]
container = argv[2]
with SwiftService(options=_opts) as swift, OutputManager() as out_manager:
    try:
        # Collect all the files and folders in the given directory
        objs = []
        dir_markers = []
        for (_dir, _ds, _fs) in walk(dir):
            if not (_ds + _fs):
                dir_markers.append(_dir)
            else:
                objs.extend([join(_dir, _f) for _f in _fs])

        # Now that we've collected all the required files and dir markers
        # build the ``SwiftUploadObject``s for the call to upload
        objs = [
            SwiftUploadObject(
                o, object_name=o.replace(
                    dir, 'my-%s-objects' % dir, 1
                )
            ) for o in objs
        ]
        dir_markers = [
            SwiftUploadObject(
                None, object_name=d.replace(
                    dir, 'my-%s-objects' % dir, 1
                ), options={'dir_marker': True}
            ) for d in dir_markers
        ]

        # Schedule uploads on the SwiftService thread pool and iterate
        # over the results
        for r in swift.upload(container, objs + dir_markers):
            if r['success']:
                if 'object' in r:
                    print(r['object'])
                elif 'for_object' in r:
                    print(
                        '%s segment %s' % (r['for_object'],
                                           r['segment_index'])
                        )
            else:
                error = r['error']
                if r['action'] == "create_container":
                    logger.warning(
                        'Warning: failed to create container '
                        "'%s'%s", container, error
                    )
                elif r['action'] == "upload_object":
                    logger.error(
                        "Failed to upload object %s to container %s: %s" %
                        (container, r['object'], error)
                    )
                else:
                    logger.error("%s" % error)

    except SwiftError as e:
        logger.error(e.value)
