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
#include <sys/poll.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

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
        struct pollfd pfds = {.fd = in, .events = POLLIN | POLLHUP};
        if (poll(&pfds, 1, -1) >= 0)
        {
            if (pfds.revents & POLLIN)
            {
                size_t bytes = 0;
                if (ioctl(in, FIONREAD, &bytes) == 0 && bytes != 0)
                {
                    size_t buf_c = 0;
                    while (ret && bytes)
                    {
                        buf_c = (bytes) < sizeof(buf) ? bytes : sizeof(buf);

                        read(in, buf, buf_c);
                        ret = f(ctx, out, buf, buf_c);

                        bytes -= buf_c;
                    }

                    maid_mem_clear(buf, sizeof(buf));
                }
                else
                {
                    ret = f(ctx, out, buf, 0);
                    break;
                }
            }
            else
            {
                ret = f(ctx, out, buf, 0);
                break;
            }
        }
    }
    maid_mem_clear(buf, sizeof(buf));

    return ret;
}

extern size_t
get_data(char *filename, u8 *out, size_t size, bool lt)
{
    /* lt = Allows smaller sizes, !lt =  Needs the exact size */

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
            {
                fprintf(stderr, "%s: %ld bytes instead of %ld\n",
                        filename, st.st_size, size);
                ret = 0;
            }
        }
        else
        {
            if (st.st_size > (ssize_t)size)
            {
                fprintf(stderr, "%s: %ld bytes when %ld is the limit\n",
                        filename, st.st_size, size);
                ret = 0;
            }
            else
                size = st.st_size;
        }
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
get_data_fd(int fd, u8 *buffer, size_t size, bool lt)
{
    size_t ret = 0;

    size_t bytes = read(fd, buffer, size);
    if (bytes == size || (lt && bytes < size))
    {
        if (read(fd, buffer, 1) == 0)
            ret = size;
        else
            fprintf(stderr, "/dev/fd/%d: longer than %ld bytes\n", fd, size);
    }
    else
        fprintf(stderr, "/dev/fd/%d: shorter than %ld bytes\n", fd, size);

    return ret;
}

extern maid_pub *
get_pub(char *filename, size_t *bits, bool private)
{
    maid_pub *ret = NULL;

    const char *next = NULL;
    struct maid_pem *p = NULL;
    static u8 buffer[65536] = {0};
    if (get_data(filename, buffer, sizeof(buffer), true) &&
        (p = maid_pem_import((char *)buffer, &next))
        && next && next[0] == '\0')
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
            struct maid_rsa_key rsa = {.modulo   = params[0],
                                       .exponent = params[2]};
            ret = maid_pub_new(maid_rsa_private, &rsa, *bits);
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
    else if (next[0] != '\0')
        fprintf(stderr, "PEM file contain a bundle\n");

    maid_mem_clear(buffer, sizeof(buffer));
    maid_pem_free(p);

    return ret;
}

/* Main functions */

extern bool
usage(void)
{
    fprintf(stderr, "A Cryptography Library for Maids\n");
    fprintf(stderr, "usage: maid [command] ...\n\n");
    fprintf(stderr, "Commands: \n");
    fprintf(stderr, "    maid stream [algorithm] [key file] [iv file]");
    fprintf(stderr, " < stream\n");
    fprintf(stderr, "    Encrypts/decrypts a stream\n");
    fprintf(stderr, "    Algorithms:\n");
    fprintf(stderr, "        aes-128-ctr (key: 16, iv: 16) \n");
    fprintf(stderr, "        aes-192-ctr (key: 24, iv: 16)\n");
    fprintf(stderr, "        aes-256-ctr (key: 32, iv: 16)\n");
    fprintf(stderr, "        chacha20    (key: 32, iv: 12)\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "    maid mac [algorithm] [key file] < message\n");
    fprintf(stderr, "    Authenticates a message\n");
    fprintf(stderr, "    Algorithms:\n");
    fprintf(stderr, "        hmac-sha224      (key:  64)\n");
    fprintf(stderr, "        hmac-sha256      (key:  64)\n");
    fprintf(stderr, "        hmac-sha384      (key: 128)\n");
    fprintf(stderr, "        hmac-sha512      (key: 128)\n");
    fprintf(stderr, "        hmac-sha512-224  (key: 128)\n");
    fprintf(stderr, "        hmac-sha512-256  (key: 128)\n");
    fprintf(stderr, "        poly1305         (key:  32)\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "    maid rng [algorithm] < entropy\n");
    fprintf(stderr, "    Pseudo-randomly generate bytes\n");
    fprintf(stderr, "    Algorithms:\n");
    fprintf(stderr, "        ctr-drbg-aes-128 (entropy: 32)\n");
    fprintf(stderr, "        ctr-drbg-aes-192 (entropy: 40)\n");
    fprintf(stderr, "        ctr-drbg-aes-256 (entropy: 48)\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "    maid hash [algorithm] < message\n");
    fprintf(stderr, "    Hashes a message\n");
    fprintf(stderr, "    Algorithms:\n");
    fprintf(stderr, "        sha224    \n");
    fprintf(stderr, "        sha256    \n");
    fprintf(stderr, "        sha384    \n");
    fprintf(stderr, "        sha512    \n");
    fprintf(stderr, "        sha512-224\n");
    fprintf(stderr, "        sha512-256\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "    maid encrypt [algorithm] [key file] [iv file] \n");
    fprintf(stderr, "                 [tag file] [aad file] < message\n");
    fprintf(stderr, "    Encrypts and generates a message tag\n");
    fprintf(stderr, "    Algorithms:\n");
    fprintf(stderr, "        aes-128-gcm      (key: 16, tag: 16, aad: any)\n");
    fprintf(stderr, "        aes-192-gcm      (key: 24, tag: 16, aad: any)\n");
    fprintf(stderr, "        aes-256-gcm      (key: 32, tag: 16, aad: any)\n");
    fprintf(stderr, "        chacha20poly1305 (key: 32, tag: 32, aad: any)\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "    maid decrypt [algorithm] [key file] [iv file] \n");
    fprintf(stderr, "                 [tag file] [aad file] < message\n");
    fprintf(stderr, "    Decrypts and validates a message tag\n");
    fprintf(stderr, "    Algorithms:\n");
    fprintf(stderr, "        aes-128-gcm      (key: 16, tag: 16, aad: any)\n");
    fprintf(stderr, "        aes-192-gcm      (key: 24, tag: 16, aad: any)\n");
    fprintf(stderr, "        aes-256-gcm      (key: 32, tag: 16, aad: any)\n");
    fprintf(stderr, "        chacha20poly1305 (key: 32, tag: 32, aad: any)\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "    maid sign [algorithm] [key file] < hash\n");
    fprintf(stderr, "    Signs a hash\n");
    fprintf(stderr, "    Algorithms:\n");
    fprintf(stderr, "        rsa-pkcs1-sha224     (key: PEM, hash: 28)\n");
    fprintf(stderr, "        rsa-pkcs1-sha256     (key: PEM, hash: 32)\n");
    fprintf(stderr, "        rsa-pkcs1-sha384     (key: PEM, hash: 48)\n");
    fprintf(stderr, "        rsa-pkcs1-sha512     (key: PEM, hash: 64)\n");
    fprintf(stderr, "        rsa-pkcs1-sha512-224 (key: PEM, hash: 28)\n");
    fprintf(stderr, "        rsa-pkcs1-sha512-256 (key: PEM, hash: 32)\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "    maid verify [algorithm] [key file] < signature\n");
    fprintf(stderr, "    Verifies a signature\n");
    fprintf(stderr, "    Algorithms:\n");
    fprintf(stderr, "        rsa-pkcs1-sha224     (key: PEM)\n");
    fprintf(stderr, "        rsa-pkcs1-sha256     (key: PEM)\n");
    fprintf(stderr, "        rsa-pkcs1-sha384     (key: PEM)\n");
    fprintf(stderr, "        rsa-pkcs1-sha512     (key: PEM)\n");
    fprintf(stderr, "        rsa-pkcs1-sha512-224 (key: PEM)\n");
    fprintf(stderr, "        rsa-pkcs1-sha512-256 (key: PEM)\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "    maid exchange [algorithm] < private\n");
    fprintf(stderr, "    Generates a public-key for key exchange\n");
    fprintf(stderr, "    Algorithms:\n");
    fprintf(stderr, "        dh-group14 (private: 256)\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "    maid secret [algorithm] [private file] < public\n");
    fprintf(stderr, "    Generates a secret from key exchange\n");
    fprintf(stderr, "    Algorithms:\n");
    fprintf(stderr, "        dh-group14 (public: 256, private: 256)\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "    maid keygen [algorithm] [generator] < entropy\n");
    fprintf(stderr, "    Generates a private key using entropy\n");
    fprintf(stderr, "    Algorithms:\n");
    fprintf(stderr, "        rsa-2048\n");
    fprintf(stderr, "        rsa-3072\n");
    fprintf(stderr, "        rsa-4096\n");
    fprintf(stderr, "    Generators:\n");
    fprintf(stderr, "        ctr-drbg-aes-128 (entropy: 32)\n");
    fprintf(stderr, "        ctr-drbg-aes-192 (entropy: 40)\n");
    fprintf(stderr, "        ctr-drbg-aes-256 (entropy: 48)\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "    maid pubkey [key file]\n");
    fprintf(stderr, "    Extracts public key from private key\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "    maid info < data\n");
    fprintf(stderr, "    Displays PEM data information\n");
    fprintf(stderr, "\n");
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
            ret = usage();

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
        ret = usage();

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
        if (strcmp(argv[1], "hmac-sha224") == 0)
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
            ret = usage();

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
        ret = usage();

    return ret;
}

extern bool
rng(int argc, char *argv[])
{
    bool ret = false;

    if (argc == 2)
    {
        ret = true;

        int in  = STDIN_FILENO;
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
            ret = usage();

        if (ret && get_data_fd(in, entropy, entropy_s, false))
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
        ret = usage();

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

        if (strcmp(argv[1], "sha224") == 0)
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
            ret = usage();

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
        ret = usage();

    return ret;
}

extern bool
encrypt_decrypt(int argc, char *argv[], bool decrypt)
{
    bool ret = false;

    if (argc == 6)
    {
        ret = true;

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
            ret = usage();

        if (ret && get_data(argv[2], key, key_s, false) &&
                   get_data(argv[3],  iv, iv_s,  false))
        {
            maid_aead *ctx = maid_aead_new(*def, key, iv);

            int fd = -1;
            if (ctx)
            {
                fd = open(argv[5], O_RDONLY);
                if (fd < 0)
                {
                    perror(argv[5]);
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
                    run_filter(ctx, (!decrypt) ? filter_encrypt :
                                                 filter_decrypt);
                    u8 tag[32] = {0};
                    maid_aead_digest(ctx, tag);
                    if (!decrypt)
                    {
                        int fd2 = open(argv[4], O_WRONLY | O_CREAT, 0644);
                        if (fd2 >= 0)
                        {
                            if (write(fd2, tag, tag_s) != tag_s)
                            {
                                perror(argv[4]);
                                ret = false;
                            }
                        }
                        else
                        {
                            perror(argv[4]);
                            ret = false;
                        }
                    }
                    else
                    {
                        u8 tag2[32] = {0};
                        ret = get_data(argv[4], tag2, tag_s, false);
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
        ret = usage();

    return ret;
}

extern bool
sign_verify(int argc, char *argv[], bool verify)
{
    bool ret = false;

    if (argc == 3)
    {
        int in  = STDIN_FILENO;
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

            if (strcmp(argv[1], "rsa-pkcs1-sha224") == 0)
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
                ret = usage();

            if (bits < min_bits)
            {
                fprintf(stderr, "Key of %lu bits is smaller than %lu\n",
                        bits, min_bits);
                ret = false;
            }

            if (ret)
            {
                ret = false;

                /* Don't use get_data_fd here */

                if (!verify)
                {
                    if (read(in, buffer, hash_s) == (ssize_t)hash_s &&
                        read(in, buffer, 1) == 0)
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
                    else
                        fprintf(stderr, "Invalid hash\n");
                }
                else
                {
                    if (read(in, buffer, sizeof(buffer)) ==
                        (ssize_t)sizeof(buffer) && read(in, buffer, 1) == 0)
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
                    else
                        fprintf(stderr, "Invalid signature\n");
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
        ret = usage();

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

    if ((!secret && argc == 2) || (secret && argc == 3))
    {
        ret = true;

        int in  = STDIN_FILENO;
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
            ret = usage();

        if (ret && !ctx)
        {
            fprintf(stderr, "Out of memory\n");
            ret = false;
        }

        if (ret)
        {
            ret = false;

            /* Don't use get_data_fd here */

            u8 buffer[key_s], buffer2[key_s];
            if (!secret)
            {
                if (read(in, buffer, key_s) == (ssize_t)key_s &&
                    read(in, buffer, 1) == 0)
                {
                    maid_kex_gpub(ctx, buffer, buffer2);
                    ret = (write(out, buffer2, key_s) == (ssize_t)key_s);
                }
                else
                    fprintf(stderr, "Invalid private key\n");
            }
            else
            {
                u8 secret[key_s];
                if (read(in, buffer, key_s) == (ssize_t)key_s &&
                    read(in, buffer, 1) == 0)
                {
                    if (get_data(argv[2], buffer2, key_s, false))
                    {
                        maid_kex_gsec(ctx, buffer2, buffer, secret);
                        ret = (write(out, secret, key_s) == (ssize_t)key_s);
                    }
                    else
                        fprintf(stderr, "Invalid private key\n");
                }
                else
                    fprintf(stderr, "Invalid public key\n");
                maid_mem_clear(secret,  sizeof(secret));
            }
            maid_mem_clear(buffer,  sizeof(buffer));
            maid_mem_clear(buffer2, sizeof(buffer2));
        }

        maid_kex_del(ctx);
    }
    else
        ret = usage();

    return ret;
}

extern bool
keygen(int argc, char *argv[])
{
    bool ret = false;

    if (argc == 3)
    {
        ret = true;

        int in = STDIN_FILENO;
        FILE *output = stdout;

        size_t bits = 0;

        if (strcmp(argv[1], "rsa-2048") == 0)
            bits = 2048;
        else if (strcmp(argv[1], "rsa-3072") == 0)
            bits = 3072;
        else if (strcmp(argv[1], "rsa-4096") == 0)
            bits = 4096;
        else
            ret = usage();

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
                ret = usage();
        }

        maid_rng *gen = NULL;
        if (ret && get_data_fd(in, entropy, entropy_s, false))
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
        ret = usage();

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
        ret = usage();

    return ret;
}

extern bool
info(int argc, char *argv[])
{
    bool ret = false;

    (void)argv;
    if (argc == 1)
    {
        int in = STDIN_FILENO;
        FILE *output = stdout;

        static u8 buffer[65536] = {0};
        if (get_data_fd(in, buffer, sizeof(buffer), true))
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
        ret = usage();

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
        else
            ret = usage();
    }
    else
        ret = usage();

    return (ret) ? EXIT_SUCCESS : ((errno) ? errno : EXIT_FAILURE);
}
