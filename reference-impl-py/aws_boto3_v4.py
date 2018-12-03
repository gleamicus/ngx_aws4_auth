#! /usr/local/bin/python3

import sys
import boto3
from botocore.client import Config

access_key = '7OF97P4N9ISW3C3W4LLF'
secret_key = 'WXMJGwWzDypOPoJ0uC5wGNoDpeZ32FbMYWSjv8yt'
endpoint_url = 'http://10.236.32.71:8085/crypto/'

s3 = boto3.client(service_name='s3',
                  region_name="us-east-1",
                  aws_access_key_id=access_key,
                  aws_secret_access_key=secret_key,
                  endpoint_url=endpoint_url, config=Config(signature_version='s3v4')
                  )

# get object
print("================== GET Single Object ==================")
try:
    result_get = s3.get_object(Bucket="replica", Key="test-small.txt")
    print(result_get['Body'].read().decode('utf-8'))

    start_byte = 0
    stop_byte = 6

    result_get = s3.get_object(Bucket='replica', Range='bytes={}-{}'.format(start_byte, stop_byte),
                               Key="test-small.txt")
    print("test-small Range: bytes=0-6: |%s| [OK]" % result_get['Body'].read().decode('utf-8'))

    result_get = s3.get_object(Bucket='replica', Range='bytes=-{}'.format(stop_byte), Key="test-small.txt")
    print("test-small Range: bytes=-6: |%s| [OK]" % result_get['Body'].read().decode('utf-8'))

    result_get = s3.get_object(Bucket='replica', Range='bytes={}-'.format(start_byte), Key="test-small.txt")
    print("test-small Range: bytes=0-: |%s| [OK]" % result_get['Body'].read().decode('utf-8'))

    start_byte = 6
    result_get = s3.get_object(Bucket='replica', Range='bytes={}-'.format(start_byte), Key="test-small.txt")
    print("test-small Range: bytes=6-: |%s| [OK]" % result_get['Body'].read().decode('utf-8'))

    print(s3.generate_presigned_url('get_object', Params={'Bucket': 'replica', 'Key': 'test-small.txt',
                                                            'ResponseContentType': 'text/plain'}, ExpiresIn=100))
except:
    print("!!!!!!!!!!!!!!!!!! GET Single Object ERROR !!!!!!!!!!!!!!!!!!")
    print("get_object error: ", sys.exc_info()[0])
print("======================================================")
print("")

print("================== GET Buckets List ==================")
try:
    result_list_buckets = s3.list_buckets()
    buckets = [bucket['Name'] for bucket in result_list_buckets['Buckets']]
    print("Bucket List: %s [OK]" % buckets)
    print(s3.generate_presigned_url('list_buckets', Params={'Key': '/'}, ExpiresIn=100))
except:
    print("!!!!!!!!!!!!!!!!!! GET Buckets List ERROR !!!!!!!!!!!!!!!!!!")
    print("list_buckets error: ", sys.exc_info()[0])
print("======================================================")
print("")

print("================== GET Buckets List ==================")
try:
    result_list_buckets = s3.list_buckets()
    buckets = [bucket['Name'] for bucket in result_list_buckets['Buckets']]
    print("Bucket List: %s [OK]" % buckets)
    print(s3.generate_presigned_url('list_buckets', Params={'Key': '/'}, ExpiresIn=100))
except:
    print("!!!!!!!!!!!!!!!!!! GET Buckets List ERROR !!!!!!!!!!!!!!!!!!")
    print("list_buckets error: ", sys.exc_info()[0])
print("======================================================")
print("")

