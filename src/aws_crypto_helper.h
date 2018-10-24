#ifndef __NGX_AWS_AUTH__CRYPTO_HELPER__
#define __NGX_AWS_AUTH__CRYPTO_HELPER__


#include <ngx_core.h>
#include <ngx_palloc.h>

ngx_str_t *ngx_aws_auth__hash_sha256(ngx_pool_t *pool, const ngx_str_t *blob);

ngx_str_t *ngx_aws_auth__sign_sha256_hex(ngx_pool_t *pool, const ngx_str_t *blob, const ngx_str_t *signing_key);

ngx_str_t *ngx_aws_auth__sign_hmac_sha256(ngx_pool_t *pool, const ngx_str_t *blob, const ngx_str_t *signing_key);

ngx_str_t *ngx_aws_auth__sign_hmac_sha256_data_only(
        ngx_pool_t *pool, const u_char *data, const int len, const ngx_str_t *signing_key);

ngx_str_t *ngx_aws_auth__sign_hmac_sha256_data_only_hex(
        ngx_pool_t *pool, const u_char *data, const int len, const ngx_str_t *signing_key);

#endif
