#! /usr/local/bin/python3

import sys
import boto3
from botocore.client import Config

access_key = '7OF97P4N9ISW3C3W4LLF'
secret_key = 'WXMJGwWzDypOPoJ0uC5wGNoDpeZ32FbMYWSjv8yt'
endpoint_url = 'http://10.236.32.71:8080/crypto/'

conn = boto3.client(service_name='s3',
                    region_name="us-east-1",
                    aws_access_key_id=access_key,
                    aws_secret_access_key=secret_key,
                    endpoint_url=endpoint_url, config=Config(signature_version='s3v4')
)

try:
    result_get = conn.get_object(Bucket="replica", Key="test-small.txt")
    print(result_get['Body'].read().decode('utf-8'))
except:
    print("get_object error: ", sys.exc_info()[0])

url = conn.generate_presigned_url('get_object', Params={'Bucket': 'replica', 'Key': 'test-small.txt',
                                                        'ResponseContentType': 'application/json'},
                                  ExpiresIn=100)
print(url)
