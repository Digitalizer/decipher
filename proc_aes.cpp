#include "pch.h"

typedef struct WORK_DATA
{
    mbedtls_aes_context context;

    unsigned char       iv[32];
    int                 ivbits;
}WORK_DATA;

static void* proc_alloc(unsigned char* key, int keybits, unsigned char* iv, int ivbits)
{
    WORK_DATA* data;

    assert(keybits == 256 || keybits == 128);
    assert(                  ivbits  == 128);

    if(keybits != 256 && keybits != 128) return NULL;
    if(                  ivbits  != 128) return NULL;

    if((data = new WORK_DATA) == NULL) return NULL;

    mbedtls_aes_init(&(data->context));

    if(mbedtls_aes_setkey_dec(&(data->context), key, keybits) != 0)
    {
        free(data);
        return NULL;
    }

    memcpy(data->iv, iv, 16);

    data->ivbits = ivbits;

    return (void*)data;
}

static void proc_free(void* handle)
{
    assert(handle);

    WORK_DATA* data = (WORK_DATA*)handle;

    mbedtls_aes_free(&(data->context));

    memset(data->iv, 0, 16);

    free(data);
}

static void proc_dec(void* handle, const unsigned char* src, unsigned char* dst, size_t length)
{
    assert(handle);

    WORK_DATA* data = (WORK_DATA*)handle;

    mbedtls_aes_crypt_cbc(&(data->context), MBEDTLS_AES_DECRYPT, length, data->iv, src, dst);
}

DECIPHER_PROC proc_aes =
{
    proc_alloc,
    proc_free,
    proc_dec
};