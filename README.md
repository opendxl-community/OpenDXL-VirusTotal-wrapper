# OpenDXL VirusTotal wrapper 

![Alt text](https://cloud.githubusercontent.com/assets/24607076/24904967/31668bd0-1eaa-11e7-84c7-717d9803a16c.png "Structure")

## Intro
[VirusTotal](https://www.virustotal.com) aggregates many antivirus products and online scan engines to check for possibles files and URLs threats.
VirusTotal's Public API lets you upload and scan files and URLs and this project focuses on an OpenDXL wrapper for this service.

## Setup

#### McAfee OpenDXL

https://www.mcafee.com/us/developers/open-dxl/index.aspx

1. Python SDK Installation [link](https://opendxl.github.io/opendxl-client-python/pydoc/installation.html)
2. Certificate Files Creation [link](https://opendxl.github.io/opendxl-client-python/pydoc/certcreation.html)
3. ePO Certificate Authority (CA) Import [link](https://opendxl.github.io/opendxl-client-python/pydoc/epocaimport.html)
4. ePO Broker Certificates Export  [link](https://opendxl.github.io/opendxl-client-python/pydoc/epobrokercertsexport.html)

#### edit the dxl.conf
```clj
[Certs]
BrokerCertChain=certs/brokercert.crt
CertFile=certs/client.crt
PrivateKey=certs/client.key

[Brokers]
{}={};8883;
```
#### VirusTotal public API service

To get an API key to use with the VirusTotal service, you’ll need to set up a free account on [VirusTotal](https://www.virustotal.com) and define the **VIRUS_TOTAL_API_KEY** variable inside the **service.py** script.

```
VIRUS_TOTAL_API_KEY = ''
```
#### DXL TOPIC
Set the variables SERVICE_INPUT and TOPIC_INPUT
```clj
SERVICE_INPUT = "/reputation"
TOPIC_INPUT = SERVICE_INPUT + "/virustotal"
```
  
## Instructions
 
1.  run the service
 
>python service.py


2.  run the client specifying the TOPIC and the destination PAYLOAD

>python client.py -t /reputation/virustotal -p https://github.com

#### Results are shown as follows:

>python client.py -t /reputation/virustotal -p 5e1295a7dd27c0f152032ed68cadf103

result is coming:

{"positives": 41, "total": 61, "verbose_msg": "Scan finished, information embedded"}

>python client.py -t /reputation/virustotal -p 1e024c1281b760bf26e7988fe35b14faf73210c8

result is coming:

{"positives": 43, "total": 61, "verbose_msg": "Scan finished, information embedded"}

>python client.py -t /reputation/virustotal -p http://www.------.com/which.exe

result is coming:

{"positives": 6, "total": 64, "verbose_msg": "Scan finished, scan information embedded in this object"}


