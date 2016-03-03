import logging

from swiftclient.service import SwiftService, SwiftError
from sys import argv

logging.basicConfig(level=logging.ERROR)
logging.getLogger("requests").setLevel(logging.CRITICAL)
logging.getLogger("swiftclient").setLevel(logging.CRITICAL)
logger = logging.getLogger(__name__)

container = argv[1]
minimum_size = 10*1024**2
with SwiftService() as swift:
    try:
        list_parts_gen = swift.list(container=container)
        for page in list_parts_gen:
            if page["success"]:
                for item in page["listing"]:

                    i_size = int(item["bytes"])
                    if i_size > minimum_size:
                        i_name = item["name"]
                        i_etag = item["hash"]
                        print(
                            "%s [size: %s] [etag: %s]" %
                            (i_name, i_size, i_etag)
                        )
            else:
                raise page["error"]

    except SwiftError as e:
        logger.error(e.value)
