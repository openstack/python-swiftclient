import logging

from swiftclient.service import SwiftService
from sys import argv


logging.basicConfig(level=logging.ERROR)
logging.getLogger("requests").setLevel(logging.CRITICAL)
logging.getLogger("swiftclient").setLevel(logging.CRITICAL)
logger = logging.getLogger(__name__)

_opts = {'object_dd_threads': 20}
container = argv[1]
objects = argv[2:]
with SwiftService(options=_opts) as swift:
    del_iter = swift.delete(container=container, objects=objects)
    for del_res in del_iter:
        c = del_res.get('container', '')
        o = del_res.get('object', '')
        a = del_res.get('attempts')
        if del_res['success'] and not del_res['action'] == 'bulk_delete':
            rd = del_res.get('response_dict')
            if rd is not None:
                t = dict(rd.get('headers', {}))
                if t:
                    print(
                        'Successfully deleted {0}/{1} in {2} attempts '
                        '(transaction id: {3})'.format(c, o, a, t)
                    )
                else:
                    print(
                        'Successfully deleted {0}/{1} in {2} '
                        'attempts'.format(c, o, a)
                    )
