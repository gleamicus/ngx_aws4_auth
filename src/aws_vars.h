
#ifndef NGX_AWS_AUTH_AWS_VARS_H
#define NGX_AWS_AUTH_AWS_VARS_H

#define AWS_S3_VARIABLE "s3_auth_token"
#define AWS_DATE_VARIABLE "aws_date"
#define AMZ_DATE_MAX_LEN 20
#define STRING_TO_SIGN_LENGTH 3000

static const ngx_str_t AWS_SIGNATURE_VERSION4_STRING = ngx_string("v4");

static const ngx_str_t EMPTY_STRING_SHA256 = ngx_string(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
static const ngx_str_t EMPTY_STRING = ngx_null_string;
static const ngx_str_t AMZ_HASH_HEADER = ngx_string("x-amz-content-sha256");
static const ngx_str_t AMZ_DATE_HEADER = ngx_string("x-amz-date");
static const ngx_str_t HOST_HEADER = ngx_string("host");
static const ngx_str_t USER_AGENT_HEADER = ngx_string("user-agent");
static const ngx_str_t USER_AGENT_VALUE = ngx_string("ngx_aws/2.0");
static const ngx_str_t AUTHZ_HEADER = ngx_string("authorization");

typedef struct {
    unsigned waiting_more_body:1;
    off_t len;
    ngx_str_t * body_sha256;
} ngx_http_data_input_ctx_t;

#endif //NGX_AWS_AUTH_AWS_VARS_H
