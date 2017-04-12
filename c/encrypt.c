#include "encrypt.h"
#include <string.h>
#if defined(USE_CRYPTO_OPENSSL)

#include <openssl/md5.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>

#elif defined(USE_CRYPTO_POLARSSL)

#include <polarssl/md5.h>
#include <polarssl/sha1.h>
#include <polarssl/aes.h>
#include <polarssl/entropy.h>
#include <polarssl/ctr_drbg.h>
#include <polarssl/version.h>
#define CIPHER_UNSUPPORTED "unsupported"

#include <time.h>
#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#else
#include <stdio.h>
#endif

#elif defined(USE_CRYPTO_MBEDTLS)

#include <mbedtls/md5.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/version.h>
#include <mbedtls/aes.h>#define MD5_BYTES 16U
#define SHA1_BYTES 20U
#define CIPHER_UNSUPPORTED "unsupported"

#include <time.h>
#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#else
#include <stdio.h>
#endif

#endif

int ss_md5_hmac(char *auth, char *msg, int msg_len, uint8_t *iv, int enc_iv_len, uint8_t *enc_key, int enc_key_len)
{
    uint8_t hash[MD5_BYTES];
    uint8_t auth_key[MAX_IV_LENGTH + MAX_KEY_LENGTH];
    memcpy(auth_key, iv, enc_iv_len);
    memcpy(auth_key + enc_iv_len, enc_key, enc_key_len);

#if defined(USE_CRYPTO_OPENSSL)
    HMAC(EVP_md5(), auth_key, enc_iv_len + enc_key_len, (uint8_t *)msg, msg_len, (uint8_t *)hash, NULL);
#elif defined(USE_CRYPTO_MBEDTLS)
    mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_MD5), auth_key, enc_iv_len + enc_key_len, (uint8_t *)msg, msg_len, (uint8_t *)hash);
#else
    md5_hmac(auth_key, enc_iv_len + enc_key_len, (uint8_t *)msg, msg_len, (uint8_t *)hash);
#endif

    memcpy(auth, hash, MD5_BYTES);

    return 0;
}

int ss_md5_hmac_with_key(char *auth, char *msg, int msg_len, uint8_t *auth_key, int key_len)
{
    uint8_t hash[MD5_BYTES];

#if defined(USE_CRYPTO_OPENSSL)
    HMAC(EVP_md5(), auth_key, key_len, (uint8_t *)msg, msg_len, (uint8_t *)hash, NULL);
#elif defined(USE_CRYPTO_MBEDTLS)
    mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_MD5), auth_key, key_len, (uint8_t *)msg, msg_len, (uint8_t *)hash);
#else
    md5_hmac(auth_key, key_len, (uint8_t *)msg, msg_len, (uint8_t *)hash);
#endif

    memcpy(auth, hash, MD5_BYTES);

    return 0;
}

int ss_md5_hash_func(char *auth, char *msg, int msg_len)
{
    uint8_t hash[MD5_BYTES];

#if defined(USE_CRYPTO_OPENSSL)
    MD5((uint8_t *)msg, msg_len, (uint8_t *)hash);
#elif defined(USE_CRYPTO_MBEDTLS)
    mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_MD5), (uint8_t *)msg, msg_len, (uint8_t *)hash);
#else
    md5((uint8_t *)msg, msg_len, (uint8_t *)hash);
#endif

    memcpy(auth, hash, MD5_BYTES);

    return 0;
}

int ss_sha1_hmac(char *auth, char *msg, int msg_len, uint8_t *iv, int enc_iv_len, uint8_t *enc_key, int enc_key_len)
{
    uint8_t hash[SHA1_BYTES];
    uint8_t auth_key[MAX_IV_LENGTH + MAX_KEY_LENGTH];
    memcpy(auth_key, iv, enc_iv_len);
    memcpy(auth_key + enc_iv_len, enc_key, enc_key_len);

#if defined(USE_CRYPTO_OPENSSL)
    HMAC(EVP_sha1(), auth_key, enc_iv_len + enc_key_len, (uint8_t *)msg, msg_len, (uint8_t *)hash, NULL);
#elif defined(USE_CRYPTO_MBEDTLS)
    mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), auth_key, enc_iv_len + enc_key_len, (uint8_t *)msg, msg_len, (uint8_t *)hash);
#else
    sha1_hmac(auth_key, enc_iv_len + enc_key_len, (uint8_t *)msg, msg_len, (uint8_t *)hash);
#endif

    memcpy(auth, hash, SHA1_BYTES);

    return 0;
}

int ss_sha1_hmac_with_key(char *auth, char *msg, int msg_len, uint8_t *auth_key, int key_len)
{
    uint8_t hash[SHA1_BYTES];

#if defined(USE_CRYPTO_OPENSSL)
    HMAC(EVP_sha1(), auth_key, key_len, (uint8_t *)msg, msg_len, (uint8_t *)hash, NULL);
#elif defined(USE_CRYPTO_MBEDTLS)
    mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), auth_key, key_len, (uint8_t *)msg, msg_len, (uint8_t *)hash);
#else
    sha1_hmac(auth_key, key_len, (uint8_t *)msg, msg_len, (uint8_t *)hash);
#endif

    memcpy(auth, hash, SHA1_BYTES);

    return 0;
}

int ss_sha1_hash_func(char *auth, char *msg, int msg_len)
{
    uint8_t hash[SHA1_BYTES];
#if defined(USE_CRYPTO_OPENSSL)
    SHA1((uint8_t *)msg, msg_len, (uint8_t *)hash);
#elif defined(USE_CRYPTO_MBEDTLS)
    mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), (uint8_t *)msg, msg_len, (uint8_t *)hash);
#else
    sha1((uint8_t *)msg, msg_len, (uint8_t *)hash);
#endif

    memcpy(auth, hash, SHA1_BYTES);

    return 0;
}

int ss_aes_128_cbc(char *encrypt, char *out_data, char *key)
{
    unsigned char iv[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

#if defined(USE_CRYPTO_OPENSSL)
    AES_KEY aes;
    AES_set_encrypt_key((unsigned char*)key, 128, &aes);
    AES_cbc_encrypt((const unsigned char *)encrypt, (unsigned char *)out_data, 16, &aes, iv, AES_ENCRYPT);

#elif defined(USE_CRYPTO_MBEDTLS)
    mbedtls_aes_context aes;

    unsigned char output[16];

    mbedtls_aes_setkey_enc( &aes, (unsigned char *)key, 128 );
    mbedtls_aes_crypt_cbc( &aes, MBEDTLS_AES_ENCRYPT, 16, iv, (unsigned char *)encrypt, output );

    memcpy(out_data, output, 16);
#else

    aes_context aes;

    unsigned char output[16];

    aes_setkey_enc( &aes, (unsigned char *)key, 128 );
    aes_crypt_cbc( &aes, AES_ENCRYPT, 16, iv, (unsigned char *)encrypt, output );

    memcpy(out_data, output, 16);
#endif

    return 0;
}

void bytes_to_key_with_size(const char *pass, size_t len, uint8_t *md, size_t md_size)
{
    uint8_t result[128];
    MD5((const unsigned char *)pass, len, result);
    memcpy(md, result, 16);
    int i = 16;
    for (; i < md_size; i += 16) {
        memcpy(result + 16, pass, len);
        MD5(result, 16 + len, result);
        memcpy(md + i, result, 16);
    }
}
