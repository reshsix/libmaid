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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include <maid/mem.h>

#include <maid/block.h>
#include <maid/stream.h>
#include <maid/mac.h>
#include <maid/aead.h>
#include <maid/hash.h>
#include <maid/pub.h>
#include <maid/sign.h>
#include <maid/kex.h>
#include <maid/serial.h>
#include <maid/keygen.h>

/* Filter functions */

static bool
filter_block_ctr(void *ctx, int out, u8 *buf, size_t buf_c)
{
    if (buf_c)
    {
        maid_block_ctr(ctx, buf, buf_c);
        write(out, buf, buf_c);
    }

    return true;
}

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
filter_encrypt(void *ctx, int out, u8 *buf, size_t buf_c)
{
    if (buf_c)
    {
        maid_aead_crypt(ctx, buf, buf_c, false);
        write(out, buf, buf_c);
    }

    return true;
}

static bool
filter_decrypt(void *ctx, int out, u8 *buf, size_t buf_c)
{
    if (buf_c)
    {
        maid_aead_crypt(ctx, buf, buf_c, true);
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

extern bool
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

extern size_t
get_data_file(char *filename, u8 *out, size_t size, bool lt)
{
    size_t ret = size;

    struct stat st = {0};
    if (stat(filename, &st) < 0)
    {
        perror(filename);
        ret = 0;
    }

    if (ret)
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
                size = st.st_size;
        }

        if (!ret)
            fprintf(stderr, "%s: %s than %ld bytes (%ld bytes)\n", filename,
                    (st.st_size < (ssize_t)size) ? "shorter" : "longer",
                    size, st.st_size);
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

    return ret;
}

extern size_t
get_data(char *input, u8 *out, size_t size, bool lt)
{
    /* lt = Allows smaller sizes, !lt =  Needs the exact size */
    size_t ret = 0;

    enum maid_mem type = 0;
    size_t conv = 0;
    if (strncmp(input, "file:", 5) == 0)
        ret = get_data_file(&(input[5]), out, size, lt);
    else if (strncmp(input, "b16l:", 5) == 0)
    {
        type = MAID_BASE16L;
        input = &(input[5]);
        conv = size * 2;
    }
    else if (strncmp(input, "b16u:", 5) == 0)
    {
        type = MAID_BASE16U;
        input = &(input[5]);
        conv = size * 2;
    }
    else if (strncmp(input, "b32:", 4) == 0)
    {
        type = MAID_BASE32;
        input = &(input[4]);
        conv = (size * 8) / 5;
    }
    else if (strncmp(input, "b32hex:", 7) == 0)
    {
        type = MAID_BASE32HEX;
        input = &(input[7]);
        conv = (size * 8) / 5;
    }
    else if (strncmp(input, "b64:", 4) == 0)
    {
        type = MAID_BASE64;
        input = &(input[4]);
        conv = (size * 4) / 3;
    }
    else if (strncmp(input, "b64url:", 7) == 0)
    {
        type = MAID_BASE64URL;
        input = &(input[7]);
        conv = (size * 4) / 3;
    }
    else if (strcmp(input, "zeros") == 0)
    {
        maid_mem_clear(out, size);
        ret = size;
    }
    else
        fprintf(stderr, "Invalid argument: '%s'\n", input);

    if (conv)
    {
        size_t len = strlen(input);
        if (len == conv || (lt && len < conv))
        {
            if (maid_mem_import(type, out, size, input, len) == len)
                ret = size;
            else
                fprintf(stderr, "Corrupted input\n");
        }
        else
            fprintf(stderr, "%s: %s than %ld chars (%ld chars)\n",
                    input, ((len < conv) ? "shorter" : "longer"), conv, len);
    }

    return ret;
}

extern maid_pub *
get_pub(char *filename, size_t *bits, bool private)
{
    maid_pub *ret = NULL;

    static u8 buffer[65536] = {0};

    const char *next = NULL;
    struct maid_pem *p = NULL, *p2 = NULL;
    if (get_data(filename, buffer, sizeof(buffer), true) &&
         (p  = maid_pem_import((char *)buffer, &next)) &&
        !(p2 = maid_pem_import(next, NULL)))
    {
        maid_mp_word *params[8] = {NULL};

        enum maid_serial t = maid_serial_import(p, bits, params);
        if (!private && (t == MAID_SERIAL_RSA_PUBLIC ||
                         t == MAID_SERIAL_PKCS8_RSA_PUBLIC))
        {
            struct maid_rsa_key rsa = {.modulo   = params[0],
                                       .exponent = params[1]};
            ret = maid_pub_new(maid_rsa_public, &rsa, *bits);
            if (!ret)
                fprintf(stderr, "Out of memory\n");
        }
        else if (private && (t == MAID_SERIAL_RSA_PRIVATE ||
                             t == MAID_SERIAL_PKCS8_RSA_PRIVATE))
        {
            struct maid_rsa_key_full rsa = {.modulo      = params[0],
                                            .encryption  = params[1],
                                            .decryption  = params[2],
                                            .prime1      = params[3],
                                            .prime2      = params[4],
                                            .exponent1   = params[5],
                                            .exponent2   = params[6],
                                            .coefficient = params[7]};
            ret = maid_pub_new(maid_rsa_private_crt, &rsa, *bits);
            if (!ret)
                fprintf(stderr, "Out of memory\n");
        }
        else if (t == MAID_SERIAL_UNKNOWN)
            fprintf(stderr, "Unknown format\n");
        else
            fprintf(stderr, "Not a %s key\n",
                    (private) ? "private" : "public");

        size_t words = maid_mp_words(*bits);
        for (size_t i = 0; i < 8; i++)
        {
            maid_mem_clear(params[i], words * sizeof(maid_mp_word));
            free(params[i]);
        }
    }
    else if (p == NULL || next == NULL)
        fprintf(stderr, "Invalid PEM file\n");
    else
        fprintf(stderr, "PEM file contain a bundle\n");

    maid_pem_free(p);
    maid_pem_free(p2);

    maid_mem_clear(buffer, sizeof(buffer));

    return ret;
}

/* Main functions */

extern bool
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
                "    encrypt     Encrypts and generates a message tag\n"
                "    decrypt     Decrypts and validates a message tag\n\n"
                "    sign        Signs a hash\n"
                "    verify      Verifies a signature\n\n"
                "    exchange    Generates a public-key for key exchange\n"
                "    secret      Generates a secret from key exchange\n\n"
                "    pubkey      Extracts public key from private key\n"
                "    info        Displays PEM data information\n\n"
                "    encode      Encodes data to a certain format\n"
                "    decode      Decodes data from a certain format\n\n"
                "Arguments:\n"
                "    file:       Binary data from a file\n"
                "    b16l:       Base16 string (lowercase)\n"
                "    b16u:       Base16 string (uppercase)\n"
                "    b32:        Base32 string\n"
                "    b32hex:     Base32 string (extended hex)\n"
                "    b64:        Base64 string\n"
                "    b64url:     Base64 string (url-safe)\n"
                "    zeros       All zeros\n");
    else if (strcmp(ctx, "stream") == 0)
        fprintf(stderr, "maid stream [algorithm] [key] [iv]"
                        " < stream\n"
                        "Encrypts/decrypts a stream\n\n"
                        "Algorithms:\n"
                        "    aes-128-ctr (key: 16, iv: 16)\n"
                        "    aes-192-ctr (key: 24, iv: 16)\n"
                        "    aes-256-ctr (key: 32, iv: 16)\n"
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
                        "    poly1305         (key:  32)\n");
    else if (strcmp(ctx, "rng") == 0)
        fprintf(stderr, "maid rng [algorithm] [entropy]\n"
                        "Pseudo-randomly generate bytes\n\n"
                        "Algorithms:\n"
                        "    ctr-drbg-aes-128 (entropy: 32)\n"
                        "    ctr-drbg-aes-192 (entropy: 40)\n"
                        "    ctr-drbg-aes-256 (entropy: 48)\n");
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
                        "    sha512-256\n");
    else if (strcmp(ctx, "encrypt") == 0)
        fprintf(stderr, "maid encrypt [algorithm] [key] [iv]"
                        " [aad file] < message\n"
                        "Encrypts and generates a message tag\n\n"
                        "Algorithms:\n"
                        "    aes-128-gcm      (key: 16, aad: any)\n"
                        "    aes-192-gcm      (key: 24, aad: any)\n"
                        "    aes-256-gcm      (key: 32, aad: any)\n"
                        "    chacha20poly1305 (key: 32, aad: any)\n");
    else if (strcmp(ctx, "decrypt") == 0)
        fprintf(stderr, "maid decrypt [algorithm] [key] [iv]"
                        " [aad file] < message\n"
                        "Decrypts and validates a message tag\n\n"
                        "Algorithms:\n"
                        "    aes-128-gcm      (key: 16, aad: any)\n"
                        "    aes-192-gcm      (key: 24, aad: any)\n"
                        "    aes-256-gcm      (key: 32, aad: any)\n"
                        "    chacha20poly1305 (key: 32, aad: any)\n");
    else if (strcmp(ctx, "sign") == 0)
        fprintf(stderr, "maid sign [algorithm] [key] [hash]\n"
                        "Signs a hash\n\n"
                        "Algorithms:\n"
                        "    rsa-pkcs1-sha1       (key: PEM, hash: 20)\n"
                        "    rsa-pkcs1-sha224     (key: PEM, hash: 28)\n"
                        "    rsa-pkcs1-sha256     (key: PEM, hash: 32)\n"
                        "    rsa-pkcs1-sha384     (key: PEM, hash: 48)\n"
                        "    rsa-pkcs1-sha512     (key: PEM, hash: 64)\n"
                        "    rsa-pkcs1-sha512-224 (key: PEM, hash: 28)\n"
                        "    rsa-pkcs1-sha512-256 (key: PEM, hash: 32)\n");
    else if (strcmp(ctx, "verify") == 0)
        fprintf(stderr, "maid verify [algorithm] [key] [signature]\n"
                        "Verifies a signature\n\n"
                        "Algorithms:\n"
                        "    rsa-pkcs1-sha1       (key: PEM)\n"
                        "    rsa-pkcs1-sha224     (key: PEM)\n"
                        "    rsa-pkcs1-sha256     (key: PEM)\n"
                        "    rsa-pkcs1-sha384     (key: PEM)\n"
                        "    rsa-pkcs1-sha512     (key: PEM)\n"
                        "    rsa-pkcs1-sha512-224 (key: PEM)\n"
                        "    rsa-pkcs1-sha512-256 (key: PEM)\n");
    else if (strcmp(ctx, "exchange") == 0)
        fprintf(stderr, "maid exchange [algorithm] [private]\n"
                        "Generates a public-key for key exchange\n\n"
                        "Algorithms:\n"
                        "    dh-group14 (private: 256)\n");
    else if (strcmp(ctx, "secret") == 0)
        fprintf(stderr, "maid secret [algorithm] [private] [public]\n"
                        "Generates a secret from key exchange\n\n"
                        "Algorithms:\n"
                        "    dh-group14 (private: 256, public: 256)\n");
    else if (strcmp(ctx, "keygen") == 0)
        fprintf(stderr, "maid keygen [algorithm] [generator] [entropy]\n"
                        "Generates a private key using entropy\n\n"
                        "Algorithms:\n"
                        "    rsa-2048\n"
                        "    rsa-3072\n"
                        "    rsa-4096\n\n"
                        "Generators:\n"
                        "    ctr-drbg-aes-128 (entropy: 32)\n"
                        "    ctr-drbg-aes-192 (entropy: 40)\n"
                        "    ctr-drbg-aes-256 (entropy: 48)\n");
    else if (strcmp(ctx, "pubkey") == 0)
        fprintf(stderr, "maid pubkey [key]\n"
                        "Extracts public key from private key\n");
    else if (strcmp(ctx, "info") == 0)
        fprintf(stderr, "maid info [data]\n"
                        "Displays PEM data information\n");
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

extern bool
stream(int argc, char *argv[])
{
    bool ret = false;

    if (argc == 4)
    {
        u8 key[32] = {0};
        u8  iv[16] = {0};

        size_t key_s = 0;
        size_t iv_s  = 0;
        const struct maid_block_def  *def_b = NULL;
        const struct maid_stream_def *def_s = NULL;

        ret = true;
        if (strcmp(argv[1], "aes-128-ctr") == 0)
        {
            key_s  = 16;
            iv_s   = 16;
            def_b   = &maid_aes_128;
        }
        else if (strcmp(argv[1], "aes-192-ctr") == 0)
        {
            key_s  = 24;
            iv_s   = 16;
            def_b  = &maid_aes_192;
        }
        else if (strcmp(argv[1], "aes-256-ctr") == 0)
        {
            key_s  = 32;
            iv_s   = 16;
            def_b  = &maid_aes_256;
        }
        else if (strcmp(argv[1], "chacha20") == 0)
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
            void *ctx = NULL;

            if (def_s)
                ctx = maid_stream_new(*def_s, key, iv, 0);
            else
                ctx = maid_block_new (*def_b, key, iv);

            if (ctx)
                run_filter(ctx, (def_s) ? filter_stream    :
                                          filter_block_ctr);
            else
                fprintf(stderr, "Out of memory\n");

            if (def_s)
                maid_stream_del(ctx);
            else
                maid_block_del(ctx);
        }

        maid_mem_clear(key, sizeof(key));
        maid_mem_clear(iv,  sizeof(iv));
    }
    else
        ret = usage("stream");

    return ret;
}

extern bool
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

extern bool
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

        if (strcmp(argv[1], "ctr-drbg-aes-128") == 0)
        {
            entropy_s = 32;
            def       = &maid_ctr_drbg_aes_128;
        }
        else if (strcmp(argv[1], "ctr-drbg-aes-192") == 0)
        {
            entropy_s = 40;
            def       = &maid_ctr_drbg_aes_192;
        }
        else if (strcmp(argv[1], "ctr-drbg-aes-256") == 0)
        {
            entropy_s = 48;
            def       = &maid_ctr_drbg_aes_256;
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

extern bool
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

extern bool
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

        if (strcmp(argv[1], "aes-128-gcm") == 0)
        {
            key_s = 16;
            iv_s  = 16;
            tag_s = 16;
            def = &maid_aes_gcm_128;
        }
        else if (strcmp(argv[1], "aes-192-gcm") == 0)
        {
            key_s = 24;
            iv_s  = 16;
            tag_s = 16;
            def = &maid_aes_gcm_192;
        }
        else if (strcmp(argv[1], "aes-256-gcm") == 0)
        {
            key_s = 32;
            iv_s  = 16;
            tag_s = 16;
            def = &maid_aes_gcm_256;
        }
        else if (strcmp(argv[1], "chacha20poly1305") == 0)
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

            int fd = -1;
            if (ctx)
            {
                fd = open(argv[4], O_RDONLY);
                if (fd < 0)
                {
                    perror(argv[4]);
                    ret = false;
                }
            }
            else
            {
                fprintf(stderr, "Out of memory\n");
                ret = false;
            }

            if (ret)
            {
                u8 buf[BUFSIZ];
                ssize_t n = 0;
                while ((n = read(fd, buf, BUFSIZ)) > 0)
                    maid_aead_update(ctx, buf, n);

                if (n >= 0)
                {
                    u8 tag[32] = {0};
                    if (!decrypt)
                    {
                        run_filter(ctx, filter_encrypt);
                        maid_aead_digest(ctx, tag);
                        write(out, tag, tag_s);
                    }
                    else
                    {
                        u8 buf[4096 * 3] = {0};
                        size_t bytes = read(in, buf, sizeof(buf) / 2);
                        if (bytes < (size_t)tag_s)
                        {
                            fprintf(stderr, "Corrupted input\n");
                            ret = false;
                        }

                        size_t bytes2 = 0;
                        for (u8 i = 0; ret; i++)
                        {
                            u8 *curr = (i % 2) ? &(buf[4096]) : buf;
                            u8 *next = (i % 2) ? buf          : &(buf[4096]);

                            bytes2 = read(in, next, sizeof(buf) / 2);
                            if (bytes == bytes2)
                            {
                                maid_aead_crypt(ctx, curr, bytes, true);
                                write(out, curr, bytes);
                            }
                            else
                            {
                                if (i % 2)
                                {
                                    for (size_t j = 0; j < 4096; j++)
                                    {
                                        u8 tmp  = curr[i];
                                        curr[i] = next[i];
                                        next[i] = tmp;
                                    }
                                }

                                size_t remain = bytes + bytes2 - tag_s;
                                memcpy(tag, &(buf[remain]), tag_s);
                                maid_aead_crypt(ctx, buf, remain, true);
                                write(out, buf, remain);
                                break;
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
                else
                    perror(argv[5]);
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

extern bool
sign_verify(int argc, char *argv[], bool verify)
{
    bool ret = false;

    if (argc == 4)
    {
        int out = STDOUT_FILENO;

        volatile size_t bits = 0;
        maid_pub *pub = get_pub(argv[2], (size_t *)&bits, !verify);

        maid_sign *ctx = NULL;
        volatile size_t words = maid_mp_words(bits);
        u8 buffer[words * sizeof(maid_mp_word)];
        maid_mem_clear(buffer, sizeof(buffer));

        if (pub && bits)
        {
            ret = true;

            const struct maid_sign_def *sign_d = NULL;
            size_t hash_s = 0;
            size_t min_bits = 0;

            if (strcmp(argv[1], "rsa-pkcs1-sha1") == 0)
            {
                sign_d   = &maid_pkcs1_v1_5_sha1;
                hash_s   = 20;
                min_bits = 2048;
            }
            else if (strcmp(argv[1], "rsa-pkcs1-sha224") == 0)
            {
                sign_d   = &maid_pkcs1_v1_5_sha224;
                hash_s   = 28;
                min_bits = 2048;
            }
            else if (strcmp(argv[1], "rsa-pkcs1-sha256") == 0)
            {
                sign_d   = &maid_pkcs1_v1_5_sha256;
                hash_s   = 32;
                min_bits = 2048;
            }
            else if (strcmp(argv[1], "rsa-pkcs1-sha384") == 0)
            {
                sign_d   = &maid_pkcs1_v1_5_sha384;
                hash_s   = 48;
                min_bits = 2048;
            }
            else if (strcmp(argv[1], "rsa-pkcs1-sha512") == 0)
            {
                sign_d   = &maid_pkcs1_v1_5_sha512;
                hash_s   = 64;
                min_bits = 2048;
            }
            else if (strcmp(argv[1], "rsa-pkcs1-sha512-224") == 0)
            {
                sign_d   = &maid_pkcs1_v1_5_sha512_224;
                hash_s   = 28;
                min_bits = 2048;
            }
            else if (strcmp(argv[1], "rsa-pkcs1-sha512-256") == 0)
            {
                sign_d   = &maid_pkcs1_v1_5_sha512_256;
                hash_s   = 32;
                min_bits = 2048;
            }
            else
                ret = usage((verify) ? "verify" : "sign");

            if (bits < min_bits)
            {
                fprintf(stderr, "Key of %lu bits is smaller than %lu\n",
                        bits, min_bits);
                ret = false;
            }

            if (ret)
            {
                ret = false;

                if (!verify && get_data(argv[3], buffer, hash_s, false))
                {
                    ctx = maid_sign_new(*sign_d, NULL, pub, bits);

                    if (ctx)
                    {
                        maid_sign_generate(ctx, buffer);
                        size_t sign_s = words * sizeof(maid_mp_word);
                        ret = (write(out, buffer, sign_s) ==
                               (ssize_t)sign_s);
                    }
                    else
                        fprintf(stderr, "Out of memory\n");
                }
                else if (get_data(argv[3], buffer, sizeof(buffer), false))
                {
                    ctx = maid_sign_new(*sign_d, pub, NULL, bits);

                    if (ctx)
                    {
                        if (maid_sign_verify(ctx, buffer))
                            ret = (write(out, buffer, hash_s) ==
                                   (ssize_t)hash_s);
                        else
                            fprintf(stderr, "Invalid signature\n");
                    }
                    else
                        fprintf(stderr, "Out of memory\n");
                }

                maid_sign_del(ctx);
            }
        }

        bits = 0;
        words = 0;
        maid_mem_clear(buffer, sizeof(buffer));
        maid_pub_del(pub);
    }
    else
        ret = usage((verify) ? "verify" : "sign");

    return ret;
}

static u8 dh_group14_mod[2048 / 8] =
    {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc9, 0x0f, 0xda, 0xa2,
     0x21, 0x68, 0xc2, 0x34, 0xc4, 0xc6, 0x62, 0x8b, 0x80, 0xdc, 0x1c, 0xd1,
     0x29, 0x02, 0x4e, 0x08, 0x8a, 0x67, 0xcc, 0x74, 0x02, 0x0b, 0xbe, 0xa6,
     0x3b, 0x13, 0x9b, 0x22, 0x51, 0x4a, 0x08, 0x79, 0x8e, 0x34, 0x04, 0xdd,
     0xef, 0x95, 0x19, 0xb3, 0xcd, 0x3a, 0x43, 0x1b, 0x30, 0x2b, 0x0a, 0x6d,
     0xf2, 0x5f, 0x14, 0x37, 0x4f, 0xe1, 0x35, 0x6d, 0x6d, 0x51, 0xc2, 0x45,
     0xe4, 0x85, 0xb5, 0x76, 0x62, 0x5e, 0x7e, 0xc6, 0xf4, 0x4c, 0x42, 0xe9,
     0xa6, 0x37, 0xed, 0x6b, 0x0b, 0xff, 0x5c, 0xb6, 0xf4, 0x06, 0xb7, 0xed,
     0xee, 0x38, 0x6b, 0xfb, 0x5a, 0x89, 0x9f, 0xa5, 0xae, 0x9f, 0x24, 0x11,
     0x7c, 0x4b, 0x1f, 0xe6, 0x49, 0x28, 0x66, 0x51, 0xec, 0xe4, 0x5b, 0x3d,
     0xc2, 0x00, 0x7c, 0xb8, 0xa1, 0x63, 0xbf, 0x05, 0x98, 0xda, 0x48, 0x36,
     0x1c, 0x55, 0xd3, 0x9a, 0x69, 0x16, 0x3f, 0xa8, 0xfd, 0x24, 0xcf, 0x5f,
     0x83, 0x65, 0x5d, 0x23, 0xdc, 0xa3, 0xad, 0x96, 0x1c, 0x62, 0xf3, 0x56,
     0x20, 0x85, 0x52, 0xbb, 0x9e, 0xd5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6d,
     0x67, 0x0c, 0x35, 0x4e, 0x4a, 0xbc, 0x98, 0x04, 0xf1, 0x74, 0x6c, 0x08,
     0xca, 0x18, 0x21, 0x7c, 0x32, 0x90, 0x5e, 0x46, 0x2e, 0x36, 0xce, 0x3b,
     0xe3, 0x9e, 0x77, 0x2c, 0x18, 0x0e, 0x86, 0x03, 0x9b, 0x27, 0x83, 0xa2,
     0xec, 0x07, 0xa2, 0x8f, 0xb5, 0xc5, 0x5d, 0xf0, 0x6f, 0x4c, 0x52, 0xc9,
     0xde, 0x2b, 0xcb, 0xf6, 0x95, 0x58, 0x17, 0x18, 0x39, 0x95, 0x49, 0x7c,
     0xea, 0x95, 0x6a, 0xe5, 0x15, 0xd2, 0x26, 0x18, 0x98, 0xfa, 0x05, 0x10,
     0x15, 0x72, 0x8e, 0x5a, 0x8a, 0xac, 0xaa, 0x68, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff};

extern bool
exchange_secret(int argc, char *argv[], bool secret)
{
    bool ret = false;

    if ((!secret && argc == 3) || (secret && argc == 4))
    {
        ret = true;

        int out = STDOUT_FILENO;

        size_t key_s = 0;
        maid_kex *ctx = NULL;
        if (strcmp(argv[1], "dh-group14") == 0)
        {
            size_t words = maid_mp_words(2048);
            key_s = 256;

            maid_mp_word g[words];
            maid_mp_word p[words];

            maid_mp_mov(words, g, NULL);
            maid_mp_mov(words, p, NULL);

            struct maid_dh_group group = {.generator = g, .modulo = p};

            g[0] = 2;
            maid_mp_read(words, p, dh_group14_mod, true);
            ctx = maid_kex_new(maid_dh, &group, 2048);
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
                maid_kex_gpub(ctx, buffer, buffer2);
                ret = (write(out, buffer2, key_s) == (ssize_t)key_s);
            }
            else
            {
                u8 secret[key_s];
                if (get_data(argv[2], buffer2, key_s, false) &&
                    get_data(argv[3], buffer,  key_s, false))
                {
                    maid_kex_gsec(ctx, buffer2, buffer, secret);
                    ret = (write(out, secret, key_s) == (ssize_t)key_s);
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

extern bool
keygen(int argc, char *argv[])
{
    bool ret = false;

    if (argc == 4)
    {
        ret = true;

        FILE *output = stdout;
        size_t bits = 0;

        if (strcmp(argv[1], "rsa-2048") == 0)
            bits = 2048;
        else if (strcmp(argv[1], "rsa-3072") == 0)
            bits = 3072;
        else if (strcmp(argv[1], "rsa-4096") == 0)
            bits = 4096;
        else
            ret = usage("keygen");

        u8 entropy[48] = {0};

        size_t entropy_s = 0;
        const struct maid_rng_def *def = NULL;

        if (ret)
        {
            if (strcmp(argv[2], "ctr-drbg-aes-128") == 0)
            {
                entropy_s = 32;
                def       = &maid_ctr_drbg_aes_128;
            }
            else if (strcmp(argv[2], "ctr-drbg-aes-192") == 0)
            {
                entropy_s = 40;
                def       = &maid_ctr_drbg_aes_192;
            }
            else if (strcmp(argv[2], "ctr-drbg-aes-256") == 0)
            {
                entropy_s = 48;
                def       = &maid_ctr_drbg_aes_256;
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
            maid_mp_word *params[8];
            size_t words = maid_keygen_rsa(bits, params, gen);

            struct maid_pem *p = NULL;
            p = maid_serial_export(MAID_SERIAL_PKCS8_RSA_PRIVATE, bits, params);
            if (p)
            {
                char *str = maid_pem_export(p);
                if (str)
                    fprintf(output, "%s\n", str);
                else
                    fprintf(stderr, "Out of memory\n");
                free(str);
            }
            else
            {
                fprintf(stderr, "Failed to export key\n");
                ret = false;
            }
            maid_pem_free(p);

            for (size_t i = 0; i < 8; i++)
            {
                maid_mem_clear(params[i], words * sizeof(maid_mp_word));
                free(params[i]);
            }
        }

        maid_rng_del(gen);
        maid_mem_clear(entropy, sizeof(entropy));
    }
    else
        ret = usage("keygen");

    return ret;
}

extern bool
pubkey(int argc, char *argv[])
{
    bool ret = false;

    if (argc == 2)
    {
        char *filename = argv[1];
        FILE *output = stdout;

        struct maid_pem *p = NULL;
        static u8 buffer[65536] = {0};
        if (get_data(filename, buffer, sizeof(buffer), true) &&
            (p = maid_pem_import((char *)buffer, NULL)))
        {
            maid_mp_word *params[8] = {NULL};
            size_t bits = 0;

            enum maid_serial t = maid_serial_import(p, &bits, params);
            size_t words = maid_mp_words(bits);
            if (t == MAID_SERIAL_RSA_PRIVATE ||
                t == MAID_SERIAL_PKCS8_RSA_PRIVATE)
            {
                struct maid_pem *p = NULL;
                p = maid_serial_export(MAID_SERIAL_PKCS8_RSA_PUBLIC,
                                       bits, params);
                if (p)
                {
                    char *str = maid_pem_export(p);
                    if (str)
                        fprintf(output, "%s\n", str);
                    else
                        fprintf(stderr, "Out of memory\n");
                    free(str);
                    ret = true;
                }
                else
                    fprintf(stderr, "Failed to export key\n");
                maid_pem_free(p);
            }
            else if (t == MAID_SERIAL_RSA_PUBLIC ||
                     t == MAID_SERIAL_PKCS8_RSA_PUBLIC)
                fprintf(stderr, "File is already a public key\n");
            else
                fprintf(stderr, "Unknown format\n");

            for (size_t i = 0; i < 8; i++)
            {
                maid_mem_clear(params[i], words * sizeof(maid_mp_word));
                free(params[i]);
            }
        }
        else if (p == NULL)
            fprintf(stderr, "Invalid PEM file\n");

        maid_mem_clear(buffer, sizeof(buffer));
        maid_pem_free(p);
    }
    else
        ret = usage("pubkey");

    return ret;
}

extern bool
info(int argc, char *argv[])
{
    bool ret = false;

    (void)argv;
    if (argc == 2)
    {
        FILE *output = stdout;

        static u8 buffer[65536] = {0};
        if (get_data(argv[1], buffer, sizeof(buffer), true))
        {
            bool empty = true;
            const char *current = (char*)buffer;
            const char *endptr  = (char*)buffer;

            while (current && current[0] != '\0')
            {
                struct maid_pem *p = maid_pem_import(current, &endptr);
                if (!p)
                    break;
                empty = false;

                maid_mp_word *params[8] = {NULL};
                size_t bits = 0;

                enum maid_serial t = maid_serial_import(p, &bits, params);
                size_t words = maid_mp_words(bits);
                if (t == MAID_SERIAL_RSA_PUBLIC ||
                    t == MAID_SERIAL_PKCS8_RSA_PUBLIC)
                {
                    fprintf(output, "RSA Public Key (%ld bits)\n\n", bits);
                    maid_mp_debug(output, words, "Modulus",  params[0], true);
                    maid_mp_debug(output, words, "Exponent", params[1], false);
                    fprintf(output, "\n");
                    ret = true;
                }
                else if (t == MAID_SERIAL_RSA_PRIVATE ||
                         t == MAID_SERIAL_PKCS8_RSA_PRIVATE)
                {
                    fprintf(output, "RSA Private Key (%ld bits)\n\n", bits);
                    maid_mp_debug(output, words, "Modulus",  params[0], true);
                    maid_mp_debug(output, words, "Public Exponent",
                                  params[1], false);
                    maid_mp_debug(output, words, "Private Exponent",
                                  params[2], true);
                    maid_mp_debug(output, words, "Prime 1",
                                  params[3], true);
                    maid_mp_debug(output, words, "Prime 2",
                                  params[4], true);
                    maid_mp_debug(output, words, "Exponent 1",
                                  params[5], true);
                    maid_mp_debug(output, words, "Exponent 2",
                                  params[6], true);
                    maid_mp_debug(output, words, "Coefficient",
                                  params[7], true);
                    ret = true;
                }
                else
                    fprintf(stderr, "Unknown format\n");

                for (size_t i = 0; i < 8; i++)
                {
                    maid_mem_clear(params[i], words * sizeof(maid_mp_word));
                    free(params[i]);
                }

                current = endptr;
                maid_pem_free(p);
            }

            if (empty)
                fprintf(stderr, "No PEM data found\n");
        }

        maid_mem_clear(buffer, sizeof(buffer));
    }
    else
        ret = usage("info");

    return ret;
}

extern bool
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
        else if (strcmp(argv[0], "pubkey") == 0)
            ret = pubkey(argc, argv);
        else if (strcmp(argv[0], "info") == 0)
            ret = info(argc, argv);
        else if (strcmp(argv[0], "encode") == 0)
            ret = encode_decode(argc, argv, false);
        else if (strcmp(argv[0], "decode") == 0)
            ret = encode_decode(argc, argv, true);
        else
            ret = usage(NULL);
    }
    else
        ret = usage(NULL);

    return (ret) ? EXIT_SUCCESS : ((errno) ? errno : EXIT_FAILURE);
}
