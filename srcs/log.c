#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <ft_malloc.h>

#define MAX_AUDIT_SIZE 1024
#define MAX_TIME_SIZE  64

static const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char* base64_encode(const uint8_t* input, size_t size, size_t* out_size)
{
    int len = size;
    int pad = (3 - len % 3) % 3;
    int output_len = 4 * ((len + 2) / 3);
    char* output = (char*)malloc(output_len + 1);

    int i, j;
    for (i = 0, j = 0; i < len;)
    {
        u_int32_t octet_a = i < len ? (unsigned char)input[i++] : 0;
        u_int32_t octet_b = i < len ? (unsigned char)input[i++] : 0;
        u_int32_t octet_c = i < len ? (unsigned char)input[i++] : 0;

        u_int32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

        output[j++] = base64_table[(triple >> 18) & 0x3F];
        output[j++] = base64_table[(triple >> 12) & 0x3F];
        output[j++] = base64_table[(triple >> 6) & 0x3F];
        output[j++] = base64_table[triple & 0x3F];
    }

    for (i = 0; i < pad; i++)
    {
        output[output_len - 1 - i] = '=';
    }
    
    output[output_len] = '\0';

    if (out_size)
    {
        *out_size = output_len;
    }

    return output;
}

void log_message(const char* filename, const char* message_format, ...)
{
    va_list args;
    char audit[MAX_AUDIT_SIZE];
    char time_str[MAX_TIME_SIZE];
    char final_message[MAX_AUDIT_SIZE + MAX_TIME_SIZE];

    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    snprintf(time_str, sizeof(time_str), "%04d-%02d-%02d %02d:%02d:%02d",
             tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
             tm->tm_hour, tm->tm_min, tm->tm_sec);

    va_start(args, message_format);
    vsnprintf(audit, MAX_AUDIT_SIZE, message_format, args);
    va_end(args);

    snprintf(final_message, sizeof(final_message), "%s %s", time_str, audit);

    size_t final_message_len = strlen(final_message);
    if (final_message[final_message_len - 1] != '\n')
    {
        if (final_message_len < sizeof(final_message) - 1)
        {
            final_message[final_message_len] = '\n';
            final_message[final_message_len + 1] = '\0';
        }
    }

    size_t encoded_size;
    char* encoded_message = base64_encode((const uint8_t*)final_message, strlen(final_message), &encoded_size);
    if (!encoded_message)
        return;

    FILE *file = fopen(filename, "a");
    if (!file)
    {
        free(encoded_message);
        return;
    }
    fprintf(file, "%s", encoded_message);
    fclose(file);

    free(encoded_message);
}
