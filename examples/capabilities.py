import logging

from swiftclient.exceptions import ClientException
from swiftclient.service import SwiftService

logging.basicConfig(level=logging.ERROR)
logging.getLogger("requests").setLevel(logging.CRITICAL)
logging.getLogger("swiftclient").setLevel(logging.CRITICAL)
logger = logging.getLogger(__name__)

with SwiftService() as swift:
    try:
        capabilities_result = swift.capabilities()
        capabilities = capabilities_result['capabilities']
        if 'slo' in capabilities:
            print('SLO is supported')
        else:
            print('SLO is not supported')
    except ClientException as e:
        logger.error(e.value)
