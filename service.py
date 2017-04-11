# The API key for invoking the Virus Total service
#_______________________________________________________________________________________
VIRUS_TOTAL_API_KEY = ''
#_______________________________________________________________________________________

SERVICE_INPUT = "/reputation"
TOPIC_INPUT = SERVICE_INPUT + "/virustotal"

VIRUS_TOTAL_URL = 'https://www.virustotal.com/vtapi/v2/'
FORMAT_ERROR = "Invalid format. MD5, SHA1, http/s URL"

import time
import logging
import os
import requests
import re
import json

from dxlclient.client import DxlClient
from dxlclient.client_config import DxlClientConfig
config = DxlClientConfig.create_dxl_config_from_file(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'dxl.conf'))

from dxlclient.message import ErrorResponse, Response

from dxlclient.callbacks import RequestCallback
from dxlclient.service import ServiceRegistrationInfo

def is_valid_MD5(buffer):
	if not re.findall(r'(?i)(?<![a-z0-9])[a-f0-9]{32}(?![a-z0-9])', buffer):
		return 0
	else:
		return 1

def is_valid_SHA1(buffer):
	if not re.findall(r'(?i)(?<![a-z0-9])[a-f0-9]{40}(?![a-z0-9])', buffer):

		return 0
	else:
		return 1

def is_valid_url(url):
    import re
    regex = re.compile(
        r'^https?://(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|)(?:/?|[/?]\S+)$', re.IGNORECASE)
    return url is not None and regex.search(url)

def json_output(verbose_msg,positives = 0,total = 0):
	out = {}
	out['verbose_msg'] = verbose_msg
	out['positives'] = positives
	out['total'] = total
	return json.dumps(out)

def virustotal(message):
	PARAMS = {'apikey': VIRUS_TOTAL_API_KEY, 'resource': message}

	if is_valid_MD5(message) or is_valid_SHA1(message) :

		try:
			response = requests.get(VIRUS_TOTAL_URL + 'file/report',params=PARAMS)
			result = response.json()
			return json_output(result['verbose_msg'],result["positives"],result["total"])
		except:
			return json_output(result['verbose_msg'])

	elif	is_valid_url(message):
			try:
				response = requests.get(VIRUS_TOTAL_URL + 'url/report',params=PARAMS)
				result = response.json()
				return json_output(result['verbose_msg'],result["positives"],result["total"])
			except:
				return json_output(result['verbose_msg'])

	else:
		return FORMAT_ERROR


# Enable logging, this will also direct built-in DXL log messages.
log_formatter = logging.Formatter('%(asctime)s %(name)s - %(levelname)s - %(message)s')

console_handler = logging.StreamHandler()
console_handler.setFormatter(log_formatter)

logger = logging.getLogger()
logger.addHandler(console_handler)
logger.setLevel(logging.INFO)

# Configure local logger
logging.getLogger().setLevel(logging.INFO)
logger = logging.getLogger(__name__)

def jsonparse(message):
#suppose the message coming is like {"PAYLOAD": "x.y.z.t", "SRC_HOST": "server_name"}
    filtered = json.loads(message)
    return str(filtered['PAYLOAD'])


with DxlClient(config) as client:

    client.connect()   
    class DxlService(RequestCallback):
        def on_request(self, request):
            try:
                query = request.payload.decode()
                logger.info("Service received request payload: " + query)
                response = Response(request)
                response.payload = str(virustotal(jsonparse(query))).encode()
                client.send_response(response)
                print response

            except Exception as ex:
                print str(ex)
                client.send_response(ErrorResponse(request, error_message=str(ex).encode()))

    info = ServiceRegistrationInfo(client, SERVICE_INPUT)
    info.add_topic(TOPIC_INPUT, DxlService())
    # Register the service with the fabric (wait up to 10 seconds for registration to complete)
    client.register_service_sync(info, 10)
    logger.info("Service is running on topic: " + TOPIC_INPUT)

    # Wait forever
    while True:
    	time.sleep(60)



