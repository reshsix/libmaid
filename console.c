/*
 *  This file is part of libmaid
 *
 *  Libmaid is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  Libmaid is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *  See the GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with libmaid; if not, see <https://www.gnu.org/licenses/>.
*/

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include <maid/mem.h>

#include <maid/stream.h>
#include <maid/mac.h>
#include <maid/aead.h>
#include <maid/hash.h>
#include <maid/ecc.h>
#include <maid/sign.h>
#include <maid/kex.h>
#include <maid/test.h>

/* Filter functions */

static bool
filter_stream(void *ctx, int out, u8 *buf, size_t buf_c)
{
    if (buf_c)
    {
        maid_stream_xor(ctx, buf, buf_c);
        write(out, buf, buf_c);
    }

    return true;
}

static bool
filter_mac(void *ctx, int out, u8 *buf, size_t buf_c)
{
    if (buf_c)
        maid_mac_update(ctx, buf, buf_c);
    else
        write(out, buf, maid_mac_digest(ctx, buf));

    return true;
}

static bool
filter_hash(void *ctx, int out, u8 *buf, size_t buf_c)
{
    if (buf_c)
        maid_hash_update(ctx, buf, buf_c);
    else
        write(out, buf, maid_hash_digest(ctx, buf));

    return true;
}

/* Command line functions */

static bool
run_filter(void *ctx, bool (*f)(void *, int, u8 *, size_t))
{
    bool ret = true;

    int in  = STDIN_FILENO;
    int out = STDOUT_FILENO;

    u8 buf[4096] = {0};
    while (ret)
    {
        size_t bytes = read(in, buf, sizeof(buf));
        ret = f(ctx, out, buf, bytes);
        if (!bytes)
            break;
    }
    maid_mem_clear(buf, sizeof(buf));

    return ret;
}

static bool get_data_fz = false;
static size_t
get_data(char *input, u8 *out, size_t size, bool lt)
{
    /* lt = Allows smaller sizes, !lt =  Needs the exact size */
    size_t ret = 0;

    /* Will be set in case return 0 is not an error */
    get_data_fz = false;

    char *org = input;
    enum maid_mem type = 0;
    size_t conv = 0;
    if (strncmp(input, "file:", 5) == 0)
    {
        char *filename = &(input[5]);
        ret = size;

        struct stat st = {0};
        if (stat(filename, &st) >= 0)
        {
            if (!lt)
            {
                if (st.st_size != (ssize_t)size)
                    ret = 0;
            }
            else
            {
                if (st.st_size > (ssize_t)size)
                    ret = 0;
                else
                {
                    size = st.st_size;

                    get_data_fz = (size == 0);
                    ret = size;
                }
            }

            if (!ret)
                fprintf(stderr, "%s: %s than %ld bytes (%ld bytes)\n", input,
                        (st.st_size < (ssize_t)size) ? "shorter" : "longer",
                        size, st.st_size);
        }
        else
        {
            perror(filename);
            ret = 0;
        }

        int in = -1;
        if (ret)
        {
            in = open(filename, O_RDONLY, 0);
            if (in < 0)
            {
                perror(filename);
                ret = 0;
            }
        }

        if (ret)
        {
            if (read(in, out, size) != (ssize_t)size)
            {
                perror(filename);
                ret = 0;
            }
            close(in);
        }
    }
    else if (strncmp(input, "hex:", 4) == 0)
    {
        type = MAID_BASE16L;
        input = &(input[4]);
        conv = size * 2;

        for (size_t i = 0; i < strlen(input); i++)
            input[i] = tolower(input[i]);
    }
    else if (strncmp(input, "b32:", 4) == 0)
    {
        type = MAID_BASE32;
        input = &(input[4]);
        conv = (size * 8) / 5;
    }
    else if (strncmp(input, "b32h:", 5) == 0)
    {
        type = MAID_BASE32HEX;
        input = &(input[5]);
        conv = (size * 8) / 5;
    }
    else if (strncmp(input, "b64:", 4) == 0)
    {
        type = MAID_BASE64;
        input = &(input[4]);
        conv = (size * 4) / 3;
    }
    else if (strncmp(input, "b64u:", 5) == 0)
    {
        type = MAID_BASE64URL;
        input = &(input[5]);
        conv = (size * 4) / 3;
    }
    else if (strncmp(input, "str:", 4) == 0)
    {
        ret = strlen(input) - 4;
        if ((!lt && ret == size) || (lt && ret <= size))
            memcpy(out, &(input[4]), ret);
        else
        {
            fprintf(stderr, "%s: %s than %ld chars (%ld chars)\n",
                    input, ((ret < size) ? "shorter" : "longer"), size, ret);
            ret = 0;
        }
    }
    else if (strcmp(input, "zero:") == 0)
    {
        maid_mem_clear(out, size);
        get_data_fz = (size == 0);
        ret = size;
    }
    else if (strcmp(input, "random:") == 0)
    {
        char *filename = "/dev/urandom";

        int in = open(filename, O_RDONLY, 0);
        if (in >= 0)
        {
            if (read(in, out, size) == (ssize_t)size)
                ret = size;
        }

        if (!ret && size)
            perror(filename);

        close(in);
    }
    else if (strcmp(input, "null:") == 0)
    {
        if (size == 0 || lt)
            get_data_fz = true;
        else
            fprintf(stderr, "%s: shorter than %ld bytes (0 bytes)\n",
                    org, size);
        ret = 0;
    }
    else
        fprintf(stderr, "Invalid argument: '%s'\n", input);

    if (conv)
    {
        size_t len = strlen(input);
        if (len == conv || (lt && len < conv))
        {
            if (maid_mem_import(type, out, size, input, len) == len)
                ret = (len * size) / conv;
            else
                fprintf(stderr, "Corrupted input\n");

            get_data_fz = (ret == 0);
        }
        else
            fprintf(stderr, "%s: %s than %ld chars (%ld chars)\n",
                    org, ((len < conv) ? "shorter" : "longer"), conv, len);
    }

    return ret;
}

/* Main functions */

static bool
usage(char *ctx)
{
    if (!ctx)
        fprintf(stderr,
                "A Cryptography Library for Maids\n"
                "usage: maid [command] [args] ...\n\n"
                "Commands:\n"
                "    stream      Encrypts/decrypts a stream\n"
                "    mac         Authenticates a message\n"
                "    rng         Pseudo-randomly generate bytes\n"
                "    hash        Hashes a message\n\n"
                "    encrypt     Encrypts a message\n"
                "    decrypt     Decrypts a message\n\n"
                "    sign        Signs a hash\n"
                "    verify      Verifies a signature\n\n"
                "    exchange    Generates a public-key for key exchange\n"
                "    secret      Generates a secret from key exchange\n\n"
                "    keygen      Generates a private key using entropy\n"
                "    pubgen      Extracts public key from private key\n\n"
                "    encode      Encodes data to a certain format\n"
                "    decode      Decodes data from a certain format\n\n"
                "Arguments:\n"
                "    file:       Binary data from a file\n"
                "    hex:        Hexadecimal string\n"
                "    b32:        Base32 string\n"
                "    b32h:       Base32 string (extended hex)\n"
                "    b64:        Base64 string\n"
                "    b64u:       Base64 string (url-safe)\n"
                "    str:        Ascii string\n"
                "    zero:       Full zeros\n"
                "    random:     Random data\n"
                "    null:       Empty argument\n");
    else if (strcmp(ctx, "stream") == 0)
        fprintf(stderr, "maid stream [algorithm] [key] [iv]"
                        " < stream\n"
                        "Encrypts/decrypts a stream\n\n"
                        "Algorithms:\n"
                        "    chacha20    (key: 32, iv: 12)\n");
    else if (strcmp(ctx, "mac") == 0)
        fprintf(stderr, "maid mac [algorithm] [key] < message\n"
                        "Authenticates a message\n\n"
                        "Algorithms:\n"
                        "    hmac-sha1        (key:  64)\n"
                        "    hmac-sha224      (key:  64)\n"
                        "    hmac-sha256      (key:  64)\n"
                        "    hmac-sha384      (key: 128)\n"
                        "    hmac-sha512      (key: 128)\n"
                        "    hmac-sha512-224  (key: 128)\n"
                        "    hmac-sha512-256  (key: 128)\n"
                        "    poly1305         (key:  32)\n"
                        "    blake2s-128      (key:  32)\n"
                        "    blake2s-160      (key:  32)\n"
                        "    blake2s-224      (key:  32)\n"
                        "    blake2s-256      (key:  32)\n"
                        "    blake2b-160      (key:  64)\n"
                        "    blake2b-256      (key:  64)\n"
                        "    blake2b-384      (key:  64)\n"
                        "    blake2b-512      (key:  64)\n");
    else if (strcmp(ctx, "rng") == 0)
        fprintf(stderr, "maid rng [algorithm] [entropy]\n"
                        "Pseudo-randomly generate bytes\n\n"
                        "Algorithms:\n"
                        "    chacha20-rng (entropy: 44)\n");
    else if (strcmp(ctx, "hash") == 0)
        fprintf(stderr, "maid hash [algorithm] < message\n"
                        "Hashes a message\n\n"
                        "Algorithms:\n"
                        "    sha1      \n"
                        "    sha224    \n"
                        "    sha256    \n"
                        "    sha384    \n"
                        "    sha512    \n"
                        "    sha512-224\n"
                        "    sha512-256\n"
                        "    blake2s-128\n"
                        "    blake2s-160\n"
                        "    blake2s-224\n"
                        "    blake2s-256\n"
                        "    blake2b-160\n"
                        "    blake2b-256\n"
                        "    blake2b-384\n"
                        "    blake2b-512\n");
    else if (strcmp(ctx, "encrypt") == 0)
        fprintf(stderr, "maid encrypt [algorithm] [key] [iv] [aad] < message\n"
                        "Encrypts a message\n\n"
                        "Algorithms:\n"
                        "    chacha20poly1305 (key: 32, iv: 12, aad <= 4k)\n");
    else if (strcmp(ctx, "decrypt") == 0)
        fprintf(stderr, "maid decrypt [algorithm] [key] [iv] [aad] < message\n"
                        "Decrypts a message\n\n"
                        "Algorithms:\n"
                        "    chacha20poly1305 (key: 32, iv: 12, aad <= 4k)\n");
    else if (strcmp(ctx, "sign") == 0)
        fprintf(stderr,
                "maid sign [algorithm] [key] [data]\n"
                "Signs a message\n\n"
                "Algorithms:\n"
                "    ed25519              (key: 32)\n");
    else if (strcmp(ctx, "verify") == 0)
        fprintf(stderr,
                "maid verify [algorithm] [key] [data] [signature]\n"
                "Verifies a signature\n\n"
                "Algorithms:\n"
                "    ed25519              (key: 32)\n");
    else if (strcmp(ctx, "exchange") == 0)
        fprintf(stderr, "maid exchange [algorithm] [private]\n"
                        "Generates a public-key for key exchange\n\n"
                        "Algorithms:\n"
                        "    x25519 (private: 32)\n");
    else if (strcmp(ctx, "secret") == 0)
        fprintf(stderr, "maid secret [algorithm] [private] [public]\n"
                        "Generates a secret from key exchange\n\n"
                        "Algorithms:\n"
                        "    x25519 (private: 32, public: 32)\n");
    else if (strcmp(ctx, "keygen") == 0)
        fprintf(stderr, "maid keygen [algorithm] [generator] [entropy]\n"
                        "Generates a private key using entropy\n\n"
                        "Algorithms:\n"
                        "    ed25519\n\n"
                        "Generators:\n"
                        "    chacha20-rng (entropy: 44)\n");
    else if (strcmp(ctx, "pubgen") == 0)
        fprintf(stderr, "maid pubgen [algorithm] [key]\n"
                        "Extracts public key from private key\n"
                        "Algorithms:\n"
                        "    ed25519 (key: OCTET STRING 32)\n");
    else if (strcmp(ctx, "encode") == 0)
        fprintf(stderr, "maid encode [algorithm] < data\n"
                        "Encodes data to a certain format\n\n"
                        "Algorithms:\n"
                        "    base16l\n"
                        "    base16u\n"
                        "    base32\n"
                        "    base32hex\n"
                        "    base64\n"
                        "    base64url\n");
    else if (strcmp(ctx, "decode") == 0)
        fprintf(stderr, "maid decode [algorithm] < data\n"
                        "Decodes data from a certain format\n\n"
                        "Algorithms:\n"
                        "    base16l\n"
                        "    base16u\n"
                        "    base32\n"
                        "    base32hex\n"
                        "    base64\n"
                        "    base64url\n");
    else
        fprintf(stderr, "maid %s: No usage text found\n", ctx);

    return false;
}

static bool
stream(int argc, char *argv[])
{
    bool ret = false;

    if (argc == 4)
    {
        ret = true;

        u8 key[32] = {0};
        u8  iv[16] = {0};

        size_t key_s = 0;
        size_t iv_s  = 0;

        const struct maid_stream_def *def_s = NULL;
        if (strcmp(argv[1], "chacha20") == 0)
        {
            key_s  = 32;
            iv_s   = 16;
            def_s  = &maid_chacha20;
        }
        else
            ret = usage("stream");

        if (ret && get_data(argv[2], key, key_s, false) &&
                   get_data(argv[3],  iv, iv_s,  false))
        {
            void *ctx = maid_stream_new(*def_s, key, iv, 0);
            if (ctx)
                run_filter(ctx, filter_stream);
            else
                fprintf(stderr, "Out of memory\n");

            maid_stream_del(ctx);
        }

        maid_mem_clear(key, sizeof(key));
        maid_mem_clear(iv,  sizeof(iv));
    }
    else
        ret = usage("stream");

    return ret;
}

static bool
mac(int argc, char *argv[])
{
    bool ret = false;

    if (argc == 3)
    {
        u8 key[128] = {0};

        size_t key_s = 0;
        const struct maid_mac_def *def = NULL;

        ret = true;
        if (strcmp(argv[1], "hmac-sha1") == 0)
        {
            key_s = 64;
            def   = &maid_hmac_sha1;
        }
        else if (strcmp(argv[1], "hmac-sha224") == 0)
        {
            key_s = 64;
            def   = &maid_hmac_sha224;
        }
        else if (strcmp(argv[1], "hmac-sha256") == 0)
        {
            key_s = 64;
            def   = &maid_hmac_sha256;
        }
        else if (strcmp(argv[1], "hmac-sha384") == 0)
        {
            key_s = 128;
            def   = &maid_hmac_sha384;
        }
        else if (strcmp(argv[1], "hmac-sha512") == 0)
        {
            key_s = 128;
            def   = &maid_hmac_sha512;
        }
        else if (strcmp(argv[1], "hmac-sha512-224") == 0)
        {
            key_s = 128;
            def   = &maid_hmac_sha512_224;
        }
        else if (strcmp(argv[1], "hmac-sha512-256") == 0)
        {
            key_s = 128;
            def   = &maid_hmac_sha512_256;
        }
        else if (strcmp(argv[1], "poly1305") == 0)
        {
            key_s = 32;
            def   = &maid_poly1305;
        }
        else if (strcmp(argv[1], "blake2s-128") == 0)
        {
            key_s = 32;
            def   = &maid_blake2s_128k;
        }
        else if (strcmp(argv[1], "blake2s-160") == 0)
        {
            key_s = 32;
            def   = &maid_blake2s_160k;
        }
        else if (strcmp(argv[1], "blake2s-224") == 0)
        {
            key_s = 32;
            def   = &maid_blake2s_224k;
        }
        else if (strcmp(argv[1], "blake2s-256") == 0)
        {
            key_s = 32;
            def   = &maid_blake2s_256k;
        }
        else if (strcmp(argv[1], "blake2b-160") == 0)
        {
            key_s = 64;
            def   = &maid_blake2b_160k;
        }
        else if (strcmp(argv[1], "blake2b-256") == 0)
        {
            key_s = 64;
            def   = &maid_blake2b_256k;
        }
        else if (strcmp(argv[1], "blake2b-384") == 0)
        {
            key_s = 64;
            def   = &maid_blake2b_384k;
        }
        else if (strcmp(argv[1], "blake2b-512") == 0)
        {
            key_s = 64;
            def   = &maid_blake2b_512k;
        }
        else
            ret = usage("mac");

        if (ret && get_data(argv[2], key, key_s, false))
        {
            maid_mac *ctx = maid_mac_new(*def, key);

            if (ctx)
                run_filter(ctx, filter_mac);
            else
                fprintf(stderr, "Out of memory\n");

            maid_mac_del(ctx);
        }

        maid_mem_clear(key, sizeof(key));
    }
    else
        ret = usage("mac");

    return ret;
}

static bool
rng(int argc, char *argv[])
{
    bool ret = false;

    if (argc == 3)
    {
        ret = true;

        int out = STDOUT_FILENO;

        u8 entropy[48] = {0};

        size_t entropy_s = 0;
        const struct maid_rng_def *def = NULL;

        if (strcmp(argv[1], "chacha20-rng") == 0)
        {
            entropy_s = 44;
            def       = &maid_chacha20_rng;
        }
        else
            ret = usage("rng");

        if (ret && get_data(argv[2], entropy, entropy_s, false))
        {
            maid_rng *ctx = maid_rng_new(*def, entropy);

            if (ctx)
            {
                u8 buffer[4096] = {0};
                while (true)
                {
                    maid_rng_generate(ctx, buffer, sizeof(buffer));
                    if (write(out, buffer, sizeof(buffer)) != sizeof(buffer))
                        break;
                }
                maid_mem_clear(buffer, sizeof(buffer));
            }
            else
                fprintf(stderr, "Out of memory\n");

            maid_rng_del(ctx);
        }

        maid_mem_clear(entropy, sizeof(entropy));
    }
    else
        ret = usage("rng");

    return ret;
}

static bool
hash(int argc, char *argv[])
{
    bool ret = false;

    if (argc == 2)
    {
        ret = true;

        const struct maid_hash_def *def = NULL;

        if (strcmp(argv[1], "sha1") == 0)
            def = &maid_sha1;
        else if (strcmp(argv[1], "sha224") == 0)
            def = &maid_sha224;
        else if (strcmp(argv[1], "sha256") == 0)
            def = &maid_sha256;
        else if (strcmp(argv[1], "sha384") == 0)
            def = &maid_sha384;
        else if (strcmp(argv[1], "sha512") == 0)
            def = &maid_sha512;
        else if (strcmp(argv[1], "sha512-224") == 0)
            def = &maid_sha512_224;
        else if (strcmp(argv[1], "sha512-256") == 0)
            def = &maid_sha512_256;
        else if (strcmp(argv[1], "blake2s-128") == 0)
            def = &maid_blake2s_128;
        else if (strcmp(argv[1], "blake2s-160") == 0)
            def = &maid_blake2s_160;
        else if (strcmp(argv[1], "blake2s-224") == 0)
            def = &maid_blake2s_224;
        else if (strcmp(argv[1], "blake2s-256") == 0)
            def = &maid_blake2s_256;
        else if (strcmp(argv[1], "blake2b-160") == 0)
            def = &maid_blake2b_160;
        else if (strcmp(argv[1], "blake2b-256") == 0)
            def = &maid_blake2b_256;
        else if (strcmp(argv[1], "blake2b-384") == 0)
            def = &maid_blake2b_384;
        else if (strcmp(argv[1], "blake2b-512") == 0)
            def = &maid_blake2b_512;
        else
            ret = usage("hash");

        if (ret)
        {
            maid_hash *ctx = maid_hash_new(*def);

            if (ctx)
                run_filter(ctx, filter_hash);
            else
                fprintf(stderr, "Out of memory\n");

            maid_hash_del(ctx);
        }
    }
    else
        ret = usage("hash");

    return ret;
}

static bool
encrypt_decrypt(int argc, char *argv[], bool decrypt)
{
    bool ret = false;

    if (argc == 5)
    {
        ret = true;

        int in  = STDIN_FILENO;
        int out = STDOUT_FILENO;

        u8  key[32] = {0};
        u8   iv[16] = {0};

        size_t  key_s = 0;
        size_t  iv_s  = 0;
        ssize_t tag_s = 0;
        const struct maid_aead_def *def = NULL;

        if (strcmp(argv[1], "chacha20poly1305") == 0)
        {
            key_s = 32;
            iv_s  = 12;
            tag_s = 32;
            def = &maid_chacha20poly1305;
        }
        else
            ret = usage((decrypt) ? "decrypt" : "encrypt");

        if (ret && get_data(argv[2], key, key_s, false) &&
                   get_data(argv[3],  iv, iv_s,  false))
        {
            maid_aead *ctx = maid_aead_new(*def, key, iv);
            if (!ctx)
            {
                fprintf(stderr, "Out of memory\n");
                ret = false;
            }

            if (ret)
            {
                u8 aad[4096] = {0};

                size_t n = get_data(argv[4], aad, sizeof(aad), true);
                if (n || get_data_fz)
                {
                    maid_aead_update(ctx, aad, n);

                    u8 buf[4096] = {0};
                    u8 tag[32]   = {0};
                    if (!decrypt)
                    {
                        while (true)
                        {
                            size_t bytes = read(in, buf, sizeof(buf));
                            if (!bytes)
                                break;

                            maid_aead_crypt(ctx, buf, bytes, false);
                            write(out, buf, bytes);
                        }

                        maid_aead_digest(ctx, tag);
                        write(out, tag, tag_s);
                    }
                    else
                    {
                        bool initialized = false;
                        size_t to_init = 0;
                        while (true)
                        {
                            size_t bytes = read(in, buf, sizeof(buf));
                            if (bytes == 0)
                            {
                                if (!initialized)
                                {
                                    fprintf(stderr, "Corrupted input\n");
                                    ret = false;
                                }
                                break;
                            }
                            else if (bytes < (size_t)tag_s)
                            {
                                if (initialized)
                                {
                                    size_t conv = tag_s - bytes;
                                    maid_aead_crypt(ctx, tag, bytes, true);
                                    write(out, tag, bytes);
                                    memmove(tag, &(tag[bytes]), conv);
                                    memcpy(&(tag[conv]), buf, bytes);
                                }
                                else
                                {
                                    memcpy(&(tag[to_init]), buf, bytes);
                                    to_init += bytes;
                                    if (to_init >= (size_t)tag_s)
                                        initialized = true;
                                }
                            }
                            else
                            {
                                if (!initialized && to_init)
                                {
                                    maid_aead_crypt(ctx, tag, to_init, true);
                                    write(out, tag, to_init);
                                }
                                else if (initialized)
                                {
                                    maid_aead_crypt(ctx, tag, tag_s, true);
                                    write(out, tag, tag_s);
                                }

                                size_t conv = bytes - tag_s;
                                memcpy(tag, &(buf[conv]), tag_s);
                                maid_aead_crypt(ctx, buf, conv, true);
                                write(out, buf, conv);
                                initialized = true;
                            }
                        }
                        maid_mem_clear(buf, sizeof(buf));

                        u8 tag2[32] = {0};
                        maid_aead_digest(ctx, tag2);
                        if (ret && memcmp(tag, tag2, tag_s) != 0)
                        {
                            fprintf(stderr, "Tag mismatch\n");
                            ret = false;
                        }
                        maid_mem_clear(tag2, sizeof(tag2));
                    }
                    maid_mem_clear(tag, sizeof(tag));
                }
            }

            maid_aead_del(ctx);
        }

        maid_mem_clear(key, sizeof(key));
        maid_mem_clear(iv,  sizeof(iv));
    }
    else
        ret = usage((decrypt) ? "decrypt" : "encrypt");

    return ret;
}

static bool
sign_verify(int argc, char *argv[], bool verify)
{
    bool ret = false;

    if ((!verify && argc == 4) || (verify && argc == 5))
    {
        u8 key[4096] = {0};
        size_t n = get_data(argv[2], key, sizeof(key), true);
        if (n)
        {
            ret = true;

            int out = STDOUT_FILENO;

            const struct maid_sign_def *sign_d = NULL;

            void *pub = NULL;
            if (strcmp(argv[1], "ed25519") == 0)
            {
                sign_d = &maid_ed25519;
                if (n == 32)
                    pub = key;
            }
            else
                ret = usage((verify) ? "verify" : "sign");

            if (ret && !pub)
            {
                fprintf(stderr, "Invalid key\n");
                ret = false;
            }

            maid_sign *ctx = NULL;
            if (ret)
            {
                if (!verify)
                    ctx = maid_sign_new(*sign_d, NULL, pub);
                else
                    ctx = maid_sign_new(*sign_d, pub, NULL);

                if (!ctx)
                {
                    fprintf(stderr, "Out of memory\n");
                    ret = false;
                }
            }

            if (ret)
            {
                u8 data[4096] = {0};
                size_t data_s = get_data(argv[3], data, sizeof(data), true);

                size_t sign_s = maid_sign_size(ctx);
                u8 sign[sign_s];
                if (verify)
                    sign_s = get_data(argv[4], sign, sizeof(sign), false);

                if ((data_s || get_data_fz) && sign_s)
                {
                    if (!verify)
                    {
                        ret = maid_sign_generate(ctx, data, data_s, sign);
                        if (ret)
                            write(out, sign, sign_s);
                        else
                            fprintf(stderr, "Signing failed\n");
                    }
                    else
                    {
                        ret = maid_sign_verify(ctx, data, data_s, sign);
                        if (!ret)
                            fprintf(stderr, "Invalid signature\n");
                    }
                }
                maid_mem_clear(data, sizeof(data));
                maid_mem_clear(sign, sizeof(sign));
            }
            maid_sign_del(ctx);
        }
    }
    else
        ret = usage((verify) ? "verify" : "sign");

    return ret;
}

static bool
exchange_secret(int argc, char *argv[], bool secret)
{
    bool ret = false;

    if ((!secret && argc == 3) || (secret && argc == 4))
    {
        ret = true;

        int out = STDOUT_FILENO;

        size_t key_s = 0;
        maid_kex *ctx = NULL;
        if (strcmp(argv[1], "x25519") == 0)
        {
            ctx   = maid_kex_new(maid_x25519);
            key_s = 32;
        }
        else
            ret = usage((secret) ? "secret" : "exchange");

        if (ret && !ctx)
        {
            fprintf(stderr, "Out of memory\n");
            ret = false;
        }

        if (ret)
        {
            ret = false;

            u8 buffer[key_s], buffer2[key_s];
            if (!secret && get_data(argv[2], buffer, key_s, false))
            {
                ret = maid_kex_pubgen(ctx, buffer, buffer2);
                if (ret)
                    ret = (write(out, buffer2, key_s) == (ssize_t)key_s);
                else
                    fprintf(stderr, "Failed to generate public key\n");
            }
            else
            {
                u8 secret[key_s];
                if (get_data(argv[2], buffer,  key_s, false) &&
                    get_data(argv[3], buffer2, key_s, false))
                {
                    ret = maid_kex_secgen(ctx, buffer, buffer2, secret);
                    if (ret)
                        ret = (write(out, secret, key_s) == (ssize_t)key_s);
                    else
                        fprintf(stderr, "Failed to generate secret\n");
                }
                maid_mem_clear(secret,  sizeof(secret));
            }
            maid_mem_clear(buffer,  sizeof(buffer));
            maid_mem_clear(buffer2, sizeof(buffer2));
        }

        maid_kex_del(ctx);
    }
    else
        ret = usage((secret) ? "secret" : "exchange");

    return ret;
}

static bool
keygen(int argc, char *argv[])
{
    bool ret = false;

    if (argc == 4)
    {
        ret = true;

        int out = STDOUT_FILENO;

        size_t type = 0;
        if (strcmp(argv[1], "ed25519") == 0)
            type = 1;
        else
            ret = usage("keygen");

        u8 entropy[48] = {0};
        size_t entropy_s = 0;

        const struct maid_rng_def *def = NULL;
        if (ret)
        {
            if (strcmp(argv[2], "chacha20-rng") == 0)
            {
                entropy_s = 44;
                def       = &maid_chacha20_rng;
            }
            else
                ret = usage("keygen");
        }

        maid_rng *gen = NULL;
        if (ret && get_data(argv[3], entropy, entropy_s, false))
        {
            gen = maid_rng_new(*def, entropy);
            if (!gen)
            {
                fprintf(stderr, "Out of memory\n");
                ret = false;
            }
        }

        if (ret)
        {
            switch (type)
            {
                case 1:;
                    maid_ecc *ed25519 = maid_ecc_new(maid_edwards25519);
                    if (ed25519)
                    {
                        u8 key[32] = {0};
                        if (maid_ecc_keygen(ed25519, key, gen))
                        {
                            write(out, key, sizeof(key));
                            ret = true;
                        }
                        else
                            fprintf(stderr, "Generation failed\n");
                        maid_mem_clear(key, sizeof(key));
                    }
                    else
                        fprintf(stderr, "Out of memory\n");
                    maid_ecc_del(ed25519);
                    break;
            }
        }

        maid_rng_del(gen);
        maid_mem_clear(entropy, sizeof(entropy));
    }
    else
        ret = usage("keygen");

    return ret;
}

static bool
pubgen(int argc, char *argv[])
{
    bool ret = false;

    if (argc == 3)
    {
        ret = true;
        int out = STDOUT_FILENO;

        u8 type = 0;
        if (strcmp(argv[1], "ed25519") == 0)
            type = 1;
        else
            ret = usage("pubgen");

        u8 data[4096] = {0};
        size_t data_s = 0;

        if (ret)
            data_s = get_data(argv[2], data, sizeof(data), true);

        if (data_s)
        {
            ret = false;
            switch (type)
            {
                case 1:;
                    maid_ecc *ed25519 = maid_ecc_new(maid_edwards25519);
                    if (ed25519)
                    {
                        u8 pub[32] = {0};
                        if (maid_ecc_pubgen(ed25519, data, pub))
                        {
                            write(out, pub, sizeof(pub));
                            ret = true;
                        }
                    }
                    maid_ecc_del(ed25519);
                    break;
                default:
                    break;
            }
        }

        maid_mem_clear(data, sizeof(data));
    }
    else
        ret = usage("pubgen");

    return ret;
}

static bool
encode_decode(int argc, char *argv[], bool decode)
{
    bool ret = false;

    if (argc == 2)
    {
        int in  = STDIN_FILENO;
        int out = STDOUT_FILENO;

        enum maid_mem type = 0;
        u8 memb = 0, forb = 0;
        if (strcmp(argv[1], "base16l") == 0)
        {
            type = MAID_BASE16L;
            memb = 1;
            forb = 2;
        }
        else if (strcmp(argv[1], "base16u") == 0)
        {
            type = MAID_BASE16U;
            memb = 1;
            forb = 2;
        }
        else if (strcmp(argv[1], "base32") == 0)
        {
            type = MAID_BASE32;
            memb = 5;
            forb = 8;
        }
        else if (strcmp(argv[1], "base32hex") == 0)
        {
            type = MAID_BASE32HEX;
            memb = 5;
            forb = 8;
        }
        else if (strcmp(argv[1], "base64") == 0)
        {
            type = MAID_BASE64;
            memb = 3;
            forb = 4;
        }
        else if (strcmp(argv[1], "base64url") == 0)
        {
            type = MAID_BASE64URL;
            memb = 3;
            forb = 4;
        }
        else
            ret = usage((decode) ? "decode" : "encode");

        if (memb && forb)
        {
            ret = true;

            if (!decode)
            {
                u8    inb[memb * 1024];
                char outb[forb * 1024];

                maid_mem_clear(inb,  sizeof(inb));
                maid_mem_clear(outb, sizeof(outb));
                while (true)
                {
                    size_t bytes = read(in, inb, sizeof(inb));
                    if (bytes == 0)
                        break;

                    size_t conv = maid_mem_export(type, inb, bytes,
                                                  outb, sizeof(outb));
                    if (conv)
                        write(out, outb, conv);
                    else
                    {
                        fprintf(stderr, "Corrupted input\n");
                        ret = false;
                        break;
                    }
                }
                maid_mem_clear(inb,  sizeof(inb));
                maid_mem_clear(outb, sizeof(outb));
            }
            else
            {
                char inb[forb * 1024];
                u8  outb[memb * 1024];

                maid_mem_clear(inb,  sizeof(inb));
                maid_mem_clear(outb, sizeof(outb));
                while (true)
                {
                    size_t bytes = read(in, inb, sizeof(inb));
                    if (bytes == 0)
                        break;

                    size_t conv = 0;
                    if ((bytes % forb) == 0 &&
                        (conv = maid_mem_import(type, outb, sizeof(outb),
                                                inb, bytes)))
                        write(out, outb, (conv * memb) / forb);
                    else
                    {
                        fprintf(stderr, "Corrupted input\n");
                        ret = false;
                        break;
                    }
                }
                maid_mem_clear(inb,  sizeof(inb));
                maid_mem_clear(outb, sizeof(outb));
            }
        }
    }
    else
        ret = usage((decode) ? "decode" : "encode");

    return ret;
}

static bool
test(int argc, char *argv[])
{
    bool ret = false;

    (void)argv;
    if (argc == 1)
    {
        u32 fails = 0;

        #define TEST(name) \
            printf("%s(): ", #name); \
            u16 name##_fails = name(); \
            if (!name##_fails) \
                printf("success\n"); \
            else \
                printf("failed %u %s\n", name##_fails, \
                       (name##_fails == 1) ? "test" : "tests"); \
            fails += name##_fails;

        /* Utilities */

        TEST(maid_test_mem)
        TEST(maid_test_mp)

        TEST(maid_test_chacha)
        TEST(maid_test_poly1305)
        TEST(maid_test_chacha20poly1305)
        TEST(maid_test_sha1)
        TEST(maid_test_sha2)
        TEST(maid_test_hmac_sha1)
        TEST(maid_test_hmac_sha2)
        TEST(maid_test_curve25519)
        TEST(maid_test_edwards25519)

        #undef TEST

        ret = (fails == 0);
    }
    else
        ret = usage("test");

    return ret;
}

extern int
main(int argc, char *argv[])
{
    bool ret = false;

    if (argc > 1)
    {
        argc -= 1;
        argv  = &(argv[1]);

        if (strcmp(argv[0], "stream") == 0)
            ret = stream(argc, argv);
        else if (strcmp(argv[0], "mac") == 0)
            ret = mac(argc, argv);
        else if (strcmp(argv[0], "rng") == 0)
            ret = rng(argc, argv);
        else if (strcmp(argv[0], "hash") == 0)
            ret = hash(argc, argv);
        else if (strcmp(argv[0], "encrypt") == 0)
            ret = encrypt_decrypt(argc, argv, false);
        else if (strcmp(argv[0], "decrypt") == 0)
            ret = encrypt_decrypt(argc, argv, true);
        else if (strcmp(argv[0], "sign") == 0)
            ret = sign_verify(argc, argv, false);
        else if (strcmp(argv[0], "verify") == 0)
            ret = sign_verify(argc, argv, true);
        else if (strcmp(argv[0], "exchange") == 0)
            ret = exchange_secret(argc, argv, false);
        else if (strcmp(argv[0], "secret") == 0)
            ret = exchange_secret(argc, argv, true);
        else if (strcmp(argv[0], "keygen") == 0)
            ret = keygen(argc, argv);
        else if (strcmp(argv[0], "pubgen") == 0)
            ret = pubgen(argc, argv);
        else if (strcmp(argv[0], "encode") == 0)
            ret = encode_decode(argc, argv, false);
        else if (strcmp(argv[0], "decode") == 0)
            ret = encode_decode(argc, argv, true);
        else if (strcmp(argv[0], "test") == 0)
            ret = test(argc, argv);
        else
            ret = usage(NULL);
    }
    else
        ret = usage(NULL);

    return (ret) ? EXIT_SUCCESS : ((errno) ? errno : EXIT_FAILURE);
}
