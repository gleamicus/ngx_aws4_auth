# AWS proxy module

This nginx module can proxy requests to authenticated S3 backends using Amazon's
V4 authentication API. The first version of this module was written for the V2
authentication protocol and can be found in the *AuthV2* branch.
The module is compatible with Ceph luminous.

## License
This project uses the same license as ngnix does i.e. the 2 clause BSD / simplified BSD / FreeBSD license

## Usage example

Implements proxying of authenticated requests to S3.

```nginx
  server {
    listen     8000;

    aws_access_key your_aws_access_key; # Example AKIDEXAMPLE
    aws_key_scope scope_of_generated_signing_key; #Example 20150830/us-east-1/service/aws4_request
    aws_signing_key signing_key_generated_using_script; #Example L4vRLWAO92X5L3Sqk5QydUSdB0nC9+1wfqLMOKLbRp4=
	aws_s3_bucket your_s3_bucket;
	
    upstream buckets {
        keepalive 60; # anable http keepalive support with the s3 servers
        server bucket1.s3.somedomain.ru weight=1 fail_timeout=1s;
        server bucket2.s3.somedomain.ru weight=1 fail_timeout=1s;
    }

    # This is an example that use specific s3 endpoint, default endpoint is s3.amazonaws.com
    location /s3_beijing {
      client_max_body_size 100m;
      client_body_buffer_size 100m;
	
      proxy_http_version 1.1;
      proxy_set_header Connection "";                   # anable keep-alive support with client
      proxy_pass http://buckets;
      proxy_set_header Host real-host;                  # real-host = <bucket>.s3domain. S3 server will use this value to check the signature

      aws_sign;
      aws_version "v4";                                 # Default v4. Could be set into v2 or v4. v2 signature version hasn't ready yet
      aws_endpoint "s3domain";                          # without bucket name
      aws_bucket "bucketname";                       # your bucket name
      aws_access_key your_aws_access_key;
      aws_signing_key signing_key_generated_using_script; # WITHOUT AWS4 PREFIX!!!! This prefix will be added automatically by ngx_aws_auth
      aws_key_scope region/service/aws4_request;        # For example: "us-east-1/s3/aws4_request". The current date will be set automatically

      aws_virtual_hosted_style_url on;                  # Will form host header for signature as aws_bucket.aws_endpoint
      aws_virtual_hosted_style_url off;                 # Will form host header for signature as aws_endpoint
    }
  }
```

## Security considerations
The V4 protocol does not need access to the actual secret keys that one obtains 
from the IAM service. The correct way to use the IAM key is to actually generate
a scoped signing key and use this signing key to access S3. This nginx module
requires the signing key and not the actual secret key. It is an insecure practise
to let the secret key reside on your nginx server.

Note that signing keys have a validity of just one week. Hence, they need to
be refreshed constantly. Please useyour favourite configuration management
system such as saltstack, puppet, chef, etc. etc. to distribute the signing
keys to your nginx clusters. Do not forget to HUP the server after placing the new
signing key as nginx reads the configuration only at startup time.

## Supported cases

* GET objects and buckets
* PUT objects and buckets
* PUT COPY objects
* DELETE objects
* ACL on objects
* GET big files and any files using HTTP ranges
* PUT mulitpart (support for uploading big files)
* HEAD objects
* OPTIONS on objects and buckets

## Known limitations
The 2.x version of the module hasn't support POST multipart form data yet. Use PUT HTTP method to create objects