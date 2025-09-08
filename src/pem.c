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

#include <stdlib.h>
#include <string.h>

#include <maid/mem.h>

#include <maid/pem.h>

extern struct maid_pem *
maid_pem_free(struct maid_pem *p)
{
    if (p)
    {
        maid_mem_clear(p->data, p->size);
        free(p->data);
    }
    free(p);
    return NULL;
}

extern struct maid_pem *
maid_pem_import(const char *input, const char **endptr)
{
    struct maid_pem *ret = NULL;

    const char *endptr2 = NULL;
    if (!endptr)
        endptr = &endptr2;

    size_t limit = (input) ? (strlen(input) * 3) / 4 : 0;
    if (limit > 32)
    {
        ret = calloc(1, sizeof(struct maid_pem));
        limit -= 32;
    }

    char *label = NULL;
    if (ret)
    {
        label = calloc(1, 49);
        ret->data  = calloc(1, limit);
        if (label && ret->data)
        {
            *endptr = input;
            input = strstr(input, "-----BEGIN ");
        }
    }

    if (*endptr && input && memcmp(input, "-----BEGIN ", 11) == 0)
    {
        const char *a = strchr(&(input[11]), '-');
        if (a && memcmp(a, "-----\n", 6) == 0)
        {
            size_t label_s = a - &(input[11]);
            if (label_s < 49)
            {
                memcpy(label, &(input[11]), label_s);
                label[label_s] = 0;

                const char *b = &(a[6]);
                const char *c = strchr(b, '-');
                if (c && memcmp(c, "-----END ", 9) == 0)
                {
                    const char *d = &(c[9]);
                    if (memcmp(d, label, label_s) == 0 &&
                        memcmp(&(d[label_s]), "-----\n", 6) == 0)
                    {
                        *endptr = &(d[label_s + 6]);

                        u8 *buffer = ret->data;
                        size_t data_s = c - b;
                        while (data_s)
                        {
                            size_t line_s = (data_s < 65) ? data_s : 65;
                            size_t byte_s = ((line_s - 1) * 3) / 4;
                            if (byte_s)
                            {
                                byte_s -= b[line_s - 2] == '=';
                                byte_s -= b[line_s - 3] == '=';
                            }

                            if (maid_mem_import(MAID_BASE64, buffer, limit,
                                                b, line_s - 1) == 0)
                            {
                                *endptr = input;
                                ret->size = 0;
                                break;
                            }
                            b = &(b[line_s]);
                            data_s -= line_s;

                            buffer     = &(buffer[byte_s]);
                            limit     -= byte_s;
                            ret->size += byte_s;
                        }
                    }
                }
            }
        }
    }

    if (ret)
    {
        if (ret->size)
        {
            if      (strcmp(label, "RSA PUBLIC KEY") == 0)
                ret->type = MAID_PEM_PUBLIC_RSA;
            else if (strcmp(label, "RSA PRIVATE KEY") == 0)
                ret->type = MAID_PEM_PRIVATE_RSA;
            else if (strcmp(label, "PUBLIC KEY") == 0)
                ret->type = MAID_PEM_PUBLIC;
            else if (strcmp(label, "PRIVATE KEY") == 0)
                ret->type = MAID_PEM_PRIVATE;
            else
                ret->type = MAID_PEM_UNKNOWN;
        }
        else
            ret = maid_pem_free(ret);
    }

    if (label)
        maid_mem_clear(label, 49);
    free(label);

    return ret;
}

extern char *
maid_pem_export(struct maid_pem *p)
{
    char *ret = NULL;

    const char *label = "UNKNOWN";
    if (p && p->data && p->size)
    {
        switch (p->type)
        {
            case MAID_PEM_PUBLIC_RSA:
                label = "RSA PUBLIC KEY";
                break;
            case MAID_PEM_PRIVATE_RSA:
                label = "RSA PRIVATE KEY";
                break;
            case MAID_PEM_PUBLIC:
                label = "PUBLIC KEY";
                break;
            case MAID_PEM_PRIVATE:
                label = "PRIVATE KEY";
                break;

            default:
                break;
        }

        size_t label_s = strlen(label);
        if (label_s && label_s < 49)
        {
            size_t usage = 1 + 32 + (label_s * 2) + ((p->size / 48) + 2) +
                           (((p->size * 4) / 3) + 4);
            ret = calloc(1, usage);
        }
    }

    if (ret)
    {
        strcpy(ret, "-----BEGIN ");
        strcat(ret, label);
        strcat(ret, "-----\n");

        u8 *in  = p->data;
        char *out = &(ret[strlen(ret)]);
        size_t size = p->size;
        while (size)
        {
            size_t limit = (size > 48) ? 48 : size;
            size_t written = maid_mem_export(MAID_BASE64, in, limit, out, 64);

            if (written == 0)
            {
                free(ret);
                ret = NULL;
                break;
            }

            out[written] = '\n';
            in  = &(in[limit]);
            out = &(out[written + 1]);
            size -= limit;
        }

        if (ret)
        {
            strcat(ret, "-----END ");
            strcat(ret, label);
            strcat(ret, "-----\n");
        }
    }

    return ret;
}
