import logging

from swiftclient.service import SwiftService, SwiftError
from sys import argv

logging.basicConfig(level=logging.ERROR)
logging.getLogger("requests").setLevel(logging.CRITICAL)
logging.getLogger("swiftclient").setLevel(logging.CRITICAL)
logger = logging.getLogger(__name__)

def is_png(obj):
    return (
        obj["name"].lower().endswith('.png') or
        obj["content_type"] == 'image/png'
    )

container = argv[1]
with SwiftService() as swift:
    try:
        list_options = {"prefix": "archive_2016-01-01/"}
        list_parts_gen = swift.list(container=container)
        for page in list_parts_gen:
            if page["success"]:
                objects = [
                    obj["name"] for obj in page["listing"] if is_png(obj)
                ]
                for down_res in swift.download(
                        container=container,
                        objects=objects):
                    if down_res['success']:
                        print("'%s' downloaded" % down_res['object'])
                    else:
                        print("'%s' download failed" % down_res['object'])
            else:
                raise page["error"]
    except SwiftError as e:
        logger.error(e.value)
