#include "pch.h"

/*

decipher

decipher [options] key:iv file_0 file_1 .... file_n

        기본값
-c      aes

*/

const char* g_format = "decipher [options] key:iv file_0 file_1 .... file_n\n"
                       "\n"
                       "\t-c : cipher method (default: aes)\n"
                       "\t     aes\n"
                       "";

#define BUFFER_SIZE 4096

unsigned char   g_buffer_enc[BUFFER_SIZE];
unsigned char   g_buffer_dec[BUFFER_SIZE];

int get_code(char letter)
{
    if(letter >= '0' && letter <= '9')
    {
        return letter - '0';
    }

    letter = tolower(letter);

    if(letter >= 'a' && letter <= 'z')
    {
        return letter - 'a' + 10;
    }

    assert(false);

    return 0;
}

void read_hex(const char* hex, unsigned char* bin, size_t len)
{
    assert(len % 2 == 0);
    assert(strlen(hex) >= len);

    for(size_t i = 0; i < len; i += 2)
    {
        *(bin++) = (get_code(*(hex + i)) << 4) |
                    get_code(*(hex + i + 1));
    }
}

void run_dec(const char* path_src, DECIPHER_PROC* decipher, unsigned char* key, int keybits, unsigned char* iv, int ivbits)
{
    assert(path_src);
    assert(decipher);

    const char*     rt         = NULL;
    HANDLE          fp_src     = INVALID_HANDLE_VALUE;
    HANDLE          fp_dst     = INVALID_HANDLE_VALUE;
    string          path_dst;
    DWORD           actual;
    DWORD           size;
    LARGE_INTEGER   size_file;
    unsigned char   pad[32]    = {0, };

    void*           context    = NULL;

    assert(path_src);

    path_dst  = path_src;
    path_dst += ".dec";

    try
    {
        if((context = decipher->proc_alloc(key, keybits, iv, ivbits)) == NULL) throw "invalid cipher";

        fp_src = CreateFileA(path_src,         GENERIC_READ,                 FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        fp_dst = CreateFileA(path_dst.c_str(), GENERIC_READ | GENERIC_WRITE, 0,               NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

        if(fp_src == INVALID_HANDLE_VALUE || fp_dst == INVALID_HANDLE_VALUE) throw "file open fail";

        while(1)
        {
            if(ReadFile(fp_src, g_buffer_enc, BUFFER_SIZE, &actual, NULL) == FALSE) throw "file read fail";

            if(actual == 0)
            {
                break;
            }

            size = actual;

            decipher->proc_dec(context, g_buffer_enc, g_buffer_dec, size);

            if(WriteFile(fp_dst, g_buffer_dec, size, &actual, NULL) == FALSE) throw "file write fail";
        }

        {
            if(GetFileSizeEx(fp_dst, &size_file) == FALSE) throw "file write fail";

            unsigned char* ptr;
            int            size_block = ivbits / 8;
            int            size_pad;
            int            i;

            if(size_file.QuadPart % (size_block) == 0)
            {
                SetFilePointer(fp_dst, -size_block, NULL, FILE_END);
                ReadFile(fp_dst, pad, size_block, &actual, NULL);

                ptr      = pad + size_block - 1;
                size_pad = *ptr;

                for(i = 0; i < size_pad; i++)
                {
                    if(*(ptr - i) != size_pad) break;
                }

                if(i == size_pad)
                {
                    SetFilePointer(fp_dst, -size_pad, NULL, FILE_END);
                    SetEndOfFile  (fp_dst);
                }
            }
        }
    }

    catch(const char* e)
    {
        rt = e;
    }

    if(fp_src)
    {
        CloseHandle(fp_src);
    }

    if(fp_dst)
    {
        CloseHandle(fp_dst);

        if(rt)
        {
            DeleteFileA(path_dst.c_str());
        }
    }

    if(context)    decipher->proc_free(context);

    if(rt) throw rt;
}

int main(int argc, char* argv[])
{
    DECIPHER_PROC*  decipher = &proc_aes;
    unsigned char   key[32];
    unsigned char   iv [32];
    int             size_key = 0;
    int             size_iv  = 0;

    try
    {
        if(argc < 3)
        {
            throw g_format;
        }

        for(int i = 1; i < argc; i++)
        {
            if(*(argv[i]) == '-')
            {
                if(strcmp("-c", argv[i]) == 0)
                {
                    if((++i) == argc) throw "invalid parameter";

                    if(strcmp("aes", argv[i]) == 0)
                    {
                        decipher = &proc_aes;
                    }
                    else
                    {
                        throw "unknown cipher method";
                    }

                    continue;
                }

                throw "invalid parameter";
            }

            if(size_key == 0)
            {
                string param_key;
                string param_iv;
                char* sep = strchr(argv[i], ':');

                if(sep == NULL) throw "invalid cipher key";

                param_key.assign(argv[i], sep - argv[i]);
                param_iv = sep + 1;

                if(param_key.size() != 32 &&
                   param_key.size() != 64 &&
                   param_iv .size() != 32 &&
                   param_iv .size() != 64) throw "invalid cipher key";

                read_hex(param_key.c_str(), key, param_key.size());
                read_hex(param_iv .c_str(), iv,  param_iv .size());

                size_key = int(param_key.size() / 2 * 8);
                size_iv  = int(param_iv .size() / 2 * 8);

                continue;
            }

            assert(size_key > 0);
            assert(size_iv  > 0);

            printf("%s -> ", argv[i]);

            try
            {
                run_dec(argv[i], decipher, key, size_key, iv, size_iv);

                printf("SUCCESS\n");
            }

            catch(const char* e)
            {
                printf("FAIL - %s\n", e);
            }
        }
    }

    catch(const char* e)
    {
        printf("\n%s\n", e);
        return -1;
    }

    return 0;
}