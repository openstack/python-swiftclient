import logging
import pprint

from swiftclient.service import SwiftService
from sys import argv

logging.basicConfig(level=logging.ERROR)
logging.getLogger("requests").setLevel(logging.CRITICAL)
logging.getLogger("swiftclient").setLevel(logging.CRITICAL)
logger = logging.getLogger(__name__)

_opts = {'object_dd_threads': 20}
with SwiftService(options=_opts) as swift:
    container = argv[1]
    objects = argv[2:]
    header_data = {}
    stats_it = swift.stat(container=container, objects=objects)
    for stat_res in stats_it:
        if stat_res['success']:
            header_data[stat_res['object']] = stat_res['headers']
        else:
            logger.error(
                'Failed to retrieve stats for %s' % stat_res['object']
            )
    pprint.pprint(header_data)
