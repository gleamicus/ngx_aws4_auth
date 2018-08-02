
#ifndef NGX_AWS_AUTH_AWS_VARS_H
#define NGX_AWS_AUTH_AWS_VARS_H


#define AWS_S3_VARIABLE "s3_auth_token"
#define AWS_DATE_VARIABLE "aws_date"

static const ngx_str_t AWS_SIGNATURE_VERSION4_STRING = ngx_string("v4");

typedef struct {
    unsigned done:1;
    unsigned waiting_more_body:1;
} ngx_http_data_input_ctx_t;

#endif //NGX_AWS_AUTH_AWS_VARS_H
