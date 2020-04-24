#pragma once

#ifndef STRICT
#define STRICT
#endif
#include <Windows.h>
#include <assert.h>
#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <string>
using namespace std;

#include "mbedtls/aes.h"

typedef struct DECIPHER_PROC
{
    void*   (*proc_alloc)   (unsigned char* key, int keybits, unsigned char* iv, int ivbits);
    void    (*proc_free)    (void* handle);
    void    (*proc_dec)     (void* handle, const unsigned char* src, unsigned char* dst, size_t length);
}DECIPHER_PROC;

extern  DECIPHER_PROC   proc_aes;