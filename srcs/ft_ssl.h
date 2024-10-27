#ifndef FT_SSL_H
#define FT_SSL_H

#include <stddef.h>
#include <stdint.h>

#define UNUSED_PARAM(x) (void)(x)
#define P_FLAG 0x0001
#define Q_FLAG 0x0002
#define R_FLAG 0x0004
#define S_FLAG 0x0008
#define A_FLAG 0x0010
#define D_FLAG 0x0020
#define E_FLAG 0x0040
#define I_FLAG 0x0080
#define K_FLAG 0x0100
#define O_FLAG 0x0200
#define V_FLAG 0x0400

#define DIGEST_FLAGS (P_FLAG | Q_FLAG | R_FLAG | S_FLAG)
#define CIPHER_FLAGS (P_FLAG | A_FLAG | D_FLAG | E_FLAG | I_FLAG | K_FLAG | O_FLAG | S_FLAG | V_FLAG)
#define BASE64_FLAGS (D_FLAG | E_FLAG | I_FLAG | O_FLAG)
#define DES_FLAGS    (P_FLAG | A_FLAG | D_FLAG | E_FLAG | I_FLAG | K_FLAG | O_FLAG | S_FLAG | V_FLAG)

typedef enum {
    TYPE_STDIN,
    TYPE_STDIN_NORMAL,
    TYPE_FILE,
    TYPE_NORMAL,
    TYPE_KEY,
    TYPE_SALT,
    TYPE_PASSWORD,
} input_type;

typedef enum {
    false,
    true
} bool;

typedef enum {
    MD5 = 0,
    SHA256,
    WHIRLPOOL,
    BLAKE2S,
    BASE64,
    DES,
    DES_ECB,
    DES_CBC,
    DES_OFB,
    DES3,
    DES3_ECB,
    DES3_CBC,
    DES3_OFB,
    HELP,
    NONE
} algorithms;

char* base64_encode(const uint8_t* input, size_t size, size_t* out_size);
char* base64_decode(const uint8_t* input, size_t size, size_t* out_size);

#endif