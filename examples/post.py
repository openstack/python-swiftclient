import logging

from swiftclient.service import SwiftService, SwiftError
from sys import argv

logging.basicConfig(level=logging.ERROR)
logging.getLogger("requests").setLevel(logging.CRITICAL)
logging.getLogger("swiftclient").setLevel(logging.CRITICAL)
logger = logging.getLogger(__name__)

container = argv[1]
with SwiftService() as swift:
    try:
        list_options = {"prefix": "archive_2016-01-01/"}
        list_parts_gen = swift.list(container=container)
        for page in list_parts_gen:
            if page["success"]:
                objects = [obj["name"] for obj in page["listing"]]
                post_options = {"header": "X-Delete-After:86400"}
                for post_res in swift.post(
                        container=container,
                        objects=objects,
                        options=post_options):
                    if post_res['success']:
                        print("Object '%s' POST success" % post_res['object'])
                    else:
                        print("Object '%s' POST failed" % post_res['object'])
            else:
                raise page["error"]
    except SwiftError as e:
        logger.error(e.value)
