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
#include <maid/hash.h>

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

extern bool
get_fixed(char *filename, u8 *out, size_t size)
{
    bool ret = true;

    struct stat st = {0};
    if (stat(filename, &st) < 0)
    {
        perror("Error checking file size");
        ret = false;
    }

    if (ret && st.st_size != size)
    {
        fprintf(stderr, "File has the wrong size: %d instead of %d\n",
                st.st_size, size);
        ret = false;
    }

    int in = -1;
    if (ret)
    {
        in = open(filename, O_RDONLY, 0);
        if (in < 0)
        {
            perror("Error opening file");
            ret = false;
        }
    }

    if (ret)
    {
        if (read(in, out, size) != size)
        {
            perror("Error reading from file");
            ret = false;
        }
        close(in);
    }

    return ret;
}

/* Main functions */

extern bool
usage(void)
{
    fprintf(stderr, "A Cryptography Library for Maids\n");
    fprintf(stderr, "usage: maid [command] ...\n\n");
    fprintf(stderr, "Commands: \n");
    fprintf(stderr, "    maid stream [algorithm] [key file] [iv file]\n");
    fprintf(stderr, "    Encrypts/decrypts a stream\n");
    fprintf(stderr, "    Algorithms:\n");
    fprintf(stderr, "        aes-128-ctr (key: 32, iv: 16) \n");
    fprintf(stderr, "        aes-192-ctr (key: 48, iv: 16)\n");
    fprintf(stderr, "        aes-256-ctr (key: 64, iv: 16)\n");
    fprintf(stderr, "        chacha20    (key: 64, iv: 12)\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "    maid mac [algorithm] [key file]\n");
    fprintf(stderr, "    Authenticates a message\n");
    fprintf(stderr, "    Algorithms:\n");
    fprintf(stderr, "        hmac-sha-224     (key:  64)\n");
    fprintf(stderr, "        hmac-sha-256     (key:  64)\n");
    fprintf(stderr, "        hmac-sha-384     (key: 128)\n");
    fprintf(stderr, "        hmac-sha-512     (key: 128)\n");
    fprintf(stderr, "        hmac-sha-512/224 (key: 128)\n");
    fprintf(stderr, "        hmac-sha-512/256 (key: 128)\n");
    fprintf(stderr, "        poly1305         (key:  32)\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "    maid hash [algorithm]\n");
    fprintf(stderr, "    Hashes a message\n");
    fprintf(stderr, "    Algorithms:\n");
    fprintf(stderr, "        sha-224    \n");
    fprintf(stderr, "        sha-256    \n");
    fprintf(stderr, "        sha-384    \n");
    fprintf(stderr, "        sha-512    \n");
    fprintf(stderr, "        sha-512/224\n");
    fprintf(stderr, "        sha-512/256\n");
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

        void *ctx = NULL;
        if      (strcmp(argv[1], "aes-128-ctr") == 0)
        {
            ret = get_fixed(argv[2], key, 16) &&
                  get_fixed(argv[3],  iv, 16) &&
                  (ctx = maid_block_new(maid_aes_128, key, iv)) &&
                  run_filter(ctx, filter_block_ctr);
            maid_block_del(ctx);
        }
        else if (strcmp(argv[1], "aes-192-ctr") == 0)
        {
            ret = get_fixed(argv[2], key, 24) &&
                  get_fixed(argv[3],  iv, 16) &&
                  (ctx = maid_block_new(maid_aes_192, key, iv)) &&
                  run_filter(ctx, filter_block_ctr);
            maid_block_del(ctx);
        }
        else if (strcmp(argv[1], "aes-256-ctr") == 0)
        {
            ret = get_fixed(argv[2], key, 32) &&
                  get_fixed(argv[3],  iv, 16) &&
                  (ctx = maid_block_new(maid_aes_256, key, iv)) &&
                  run_filter(ctx, filter_block_ctr);
            maid_block_del(ctx);
        }
        else if (strcmp(argv[1], "chacha20") == 0)
        {
            ret = get_fixed(argv[2], key, 32) &&
                  get_fixed(argv[3],  iv, 12) &&
                  (ctx = maid_stream_new(maid_chacha20, key, iv, 0)) &&
                  run_filter(ctx, filter_stream);
            maid_stream_del(ctx);
        }
        else
            ret = usage();

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
        u8 key[32] = {0};

        void *ctx = NULL;
        if      (strcmp(argv[1], "hmac-sha224") == 0)
            ret = get_fixed(argv[2], key, 64) &&
                  (ctx = maid_mac_new(maid_hmac_sha224, key));
        else if (strcmp(argv[1], "hmac-sha256") == 0)
            ret = get_fixed(argv[2], key, 64) &&
                  (ctx = maid_mac_new(maid_hmac_sha256, key));
        else if (strcmp(argv[1], "hmac-sha384") == 0)
            ret = get_fixed(argv[2], key, 128) &&
                  (ctx = maid_mac_new(maid_hmac_sha384, key));
        else if (strcmp(argv[1], "hmac-sha512") == 0)
            ret = get_fixed(argv[2], key, 128) &&
                  (ctx = maid_mac_new(maid_hmac_sha512, key));
        else if (strcmp(argv[1], "hmac-sha512/224") == 0)
            ret = get_fixed(argv[2], key, 128) &&
                  (ctx = maid_mac_new(maid_hmac_sha512_224, key));
        else if (strcmp(argv[1], "hmac-sha512/256") == 0)
            ret = get_fixed(argv[2], key, 128) &&
                  (ctx = maid_mac_new(maid_hmac_sha512_256, key));
        else if (strcmp(argv[1], "poly1305") == 0)
            ret = get_fixed(argv[2], key, 32) &&
                  (ctx = maid_mac_new(maid_poly1305, key));
        else
            ret = usage();

        if (ret)
        {
            run_filter(ctx, filter_mac);
            maid_mac_del(ctx);
        }

        maid_mem_clear(key, sizeof(key));
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
        void *ctx = NULL;
        if      (strcmp(argv[1], "sha224") == 0)
            ret = (ctx = maid_hash_new(maid_sha224));
        else if (strcmp(argv[1], "sha256") == 0)
            ret = (ctx = maid_hash_new(maid_sha256));
        else if (strcmp(argv[1], "sha384") == 0)
            ret = (ctx = maid_hash_new(maid_sha384));
        else if (strcmp(argv[1], "sha512") == 0)
            ret = (ctx = maid_hash_new(maid_sha512));
        else if (strcmp(argv[1], "sha512/224") == 0)
            ret = (ctx = maid_hash_new(maid_sha512_224));
        else if (strcmp(argv[1], "sha512/256") == 0)
            ret = (ctx = maid_hash_new(maid_sha512_256));
        else
            ret = usage();

        if (ret)
        {
            run_filter(ctx, filter_hash);
            maid_hash_del(ctx);
        }
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
        else if (strcmp(argv[0], "hash") == 0)
            ret = hash(argc, argv);
        else
            ret = usage();
    }
    else
        ret = usage();

    return (ret) ? EXIT_SUCCESS : ((!errno) ? errno : 1);
}
