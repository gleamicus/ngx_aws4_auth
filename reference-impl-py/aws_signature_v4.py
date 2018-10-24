#! /usr/local/bin/python3

# AWS Version 4 signing example

# EC2 API (DescribeRegions)

# See: http://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html
# This version makes a GET request and passes the signature
# in the Authorization header.
import sys, os, base64, datetime, hashlib, hmac
import requests  # pip install requests

# ************* REQUEST VALUES *************
method = 'GET'
service = 's3'
host = 's3.somehost.ru'
region = 'us-east-1'
endpoint = 'http://s3.somehost.ru:7480/replica/somefile.txt'
canonical_uri = '/replica/movie_lines.txt'
request_parameters = 'uploadId=2~bwo8RA7c2d39-M8iySk-DexX90yXp8I'
# amzdate = '20181024T141346Z'
# datestamp = '20181024'

amzdate = ''
datestamp = ''

access_key = '7OF97P4N9ISW3C3W4LLF'
secret_key = 'WXMJGwWzDypOPoJ0uC5wGNoDpeZ32FbMYWSjv8yt'

body = ''


# Key derivation functions. See:
# http://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html#signature-v4-examples-python
def sign(key, msg):
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()


def signHEX(key, msg):
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).hexdigest().lower()


def getSignatureKey(key, dateStamp, regionName, serviceName):
    kDate = sign(('AWS4' + key).encode('utf-8'), dateStamp)
    kDateHEX = signHEX(('AWS4' + key).encode('utf-8'), dateStamp)
    kRegion = sign(kDate, regionName)
    kRegionHEX = signHEX(kDate, regionName)
    kService = sign(kRegion, serviceName)
    kServiceHEX = signHEX(kRegion, serviceName)
    kSigning = sign(kService, 'aws4_request')
    kSigningHEX = signHEX(kService, 'aws4_request')

    print('Signature++++++++++++++++++++++++++++++++++++')
    print('Hashes: ')
    print('\tkSecret: %s' % ("AWS4" + key))
    print('\tkDate: %s' % kDateHEX)
    print('\tkRegion: %s' % kRegionHEX)
    print('\tkService: %s' % kServiceHEX)
    print('\tkSigning: %s' % kSigningHEX)

    return kSigning


# Read AWS access key from env. variables or configuration file. Best practice is NOT
# to embed credentials in code.
if len(access_key) == 0:
    access_key = os.environ.get('AWS_ACCESS_KEY_ID')

if len(secret_key) == 0:
    secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')

if access_key is None or secret_key is None:
    print('No access key is available.')
    sys.exit()

# Create a date for headers and the credential string
t = datetime.datetime.utcnow()
if (not amzdate):
    amzdate = t.strftime('%Y%m%dT%H%M%SZ')
if (not datestamp):
    datestamp = t.strftime('%Y%m%d')

# Date w/o time, used in credential scope

# ************* TASK 1: CREATE A CANONICAL REQUEST *************
# http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html

# Step 1 is to define the verb (GET, POST, etc.)--already done.

# Step 2: Create canonical URI--the part of the URI from domain to query 
# string (use '/' if no path)

# Step 3: Create the canonical query string. In this example (a GET request),
# request parameters are in the query string. Query string values must
# be URL-encoded (space=%20). The parameters must be sorted by name.
# For this example, the query string is pre-formatted in the request_parameters variable.
canonical_querystring = request_parameters

# Step 6: Create payload hash (hash of the request body content). For GET
# requests, the payload is an empty string ("").
payload_hash = hashlib.sha256((body).encode('utf-8')).hexdigest()

# Step 4: Create the canonical headers and signed headers. Header names
# must be trimmed and lowercase, and sorted in code point order from
# low to high. Note that there is a trailing \n.
canonical_headers = 'host:' + host + '\n' + 'x-amz-content-sha256:' + payload_hash + '\n' + 'x-amz-date:' + amzdate + '\n'

# Step 5: Create the list of signed headers. This lists the headers
# in the canonical_headers list, delimited with ";" and in alpha order.
# Note: The request can include any headers; canonical_headers and
# signed_headers lists those that you want to be included in the 
# hash of the request. "Host" and "x-amz-date" are always required.
signed_headers = 'host;x-amz-content-sha256;x-amz-date'

# Step 7: Combine elements to create canonical request
canonical_request = method + '\n' + canonical_uri + '\n' + canonical_querystring + '\n' + canonical_headers + '\n' + signed_headers + '\n' + payload_hash

print('Canonical request: ' + canonical_request)

# ************* TASK 2: CREATE THE STRING TO SIGN*************
# Match the algorithm to the hashing algorithm you use, either SHA-1 or
# SHA-256 (recommended)
algorithm = 'AWS4-HMAC-SHA256'
credential_scope = datestamp + '/' + region + '/' + service + '/' + 'aws4_request'
string_to_sign = algorithm + '\n' + amzdate + '\n' + credential_scope + '\n' + hashlib.sha256(
    canonical_request.encode('utf-8')).hexdigest()

# ************* TASK 3: CALCULATE THE SIGNATURE *************
# Create the signing key using the function defined above.
signing_key = getSignatureKey(secret_key, datestamp, region, service)

# Sign the string_to_sign using the signing_key
signature = hmac.new(signing_key, (string_to_sign).encode('utf-8'), hashlib.sha256).hexdigest()

print('string_to_sign: %s' % string_to_sign)
print('Signature: %s' % signature)

# ************* TASK 4: ADD SIGNING INFORMATION TO THE REQUEST *************
# The signing information can be either in a query string value or in 
# a header named Authorization. This code shows how to use a header.
# Create authorization header and add to request headers
authorization_header = algorithm + ' ' + 'Credential=' + access_key + '/' + credential_scope + ', ' + 'SignedHeaders=' + signed_headers + ', ' + 'Signature=' + signature

# The request can include any headers, but MUST include "host", "x-amz-date", 
# and (for this scenario) "Authorization". "host" and "x-amz-date" must
# be included in the canonical_headers and signed_headers, as noted
# earlier. Order here is not significant.
# Python note: The 'host' header is added automatically by the Python 'requests' library.
headers = {'host': host, 'x-amz-date': amzdate, 'x-amz-content-sha256': payload_hash, 'Authorization': authorization_header}

# ************* SEND THE REQUEST *************
if len(canonical_querystring) == 0:
    request_url = endpoint
else:
    request_url = endpoint + '?' + canonical_querystring

print('\nBEGIN REQUEST++++++++++++++++++++++++++++++++++++')
print('Request URL = ' + request_url)
r = requests.get(request_url, headers=headers)

print('\nRESPONSE++++++++++++++++++++++++++++++++++++')
print('Response code: %d\n' % r.status_code)
print(r.text)

exit(0)
