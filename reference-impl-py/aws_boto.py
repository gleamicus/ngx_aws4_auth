#! /usr/local/bin/python

import boto.s3.connection
from urllib.parse import urlencode, quote_plus


c = boto.s3.connection.S3Connection(
    host='10.236.32.71', port=9090, is_secure=False,
    aws_access_key_id='7OF97P4N9ISW3C3W4LLF',
    aws_secret_access_key='WXMJGwWzDypOPoJ0uC5wGNoDpeZ32FbMYWSjv8yt',
    calling_format='boto.s3.connection.OrdinaryCallingFormat'
)

# b = c.get_bucket('replica', validate=False)
# key = b.get_key('test-small.txt', validate=False)
# url = key.generate_url(expires_in=0, response_headers={'response-content-type': 'application/json'})
# content = key.read()
url = c.generate_url(expires_in=100, method='GET', bucket='replica',
                    key='test-small.txt',
                    response_headers={'response-content-type': 'application/json', 'test': '123'})

print(url)
