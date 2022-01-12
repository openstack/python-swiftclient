import logging

from swiftclient.service import SwiftService, SwiftCopyObject, SwiftError

logging.basicConfig(level=logging.ERROR)
logging.getLogger("requests").setLevel(logging.CRITICAL)
logging.getLogger("swiftclient").setLevel(logging.CRITICAL)
logger = logging.getLogger(__name__)

with SwiftService() as swift:
    try:
        obj = SwiftCopyObject("c", {"destination": "/cont/d"})
        for i in swift.copy(
                "cont", ["a", "b", obj],
                {"meta": ["foo:bar"], "destination": "/cc"}):
            if i["success"]:
                if i["action"] == "copy_object":
                    print(
                        "object %s copied from /%s/%s" %
                        (i["destination"], i["container"], i["object"])
                    )
                elif i["action"] == "create_container":
                    print(
                        "container %s created" % i["container"]
                    )
            else:
                if "error" in i and isinstance(i["error"], Exception):
                    raise i["error"]
    except SwiftError as e:
        logger.error(e.value)
