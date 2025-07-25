#ifndef BINARY_H
#define BINARY_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
typedef uint8_t bit8;
typedef uint16_t bit16;
typedef uint32_t bit32;
typedef uint64_t bit64;
typedef int8_t sBit8;
typedef int16_t sBit16;
typedef int32_t sBit32;
typedef int64_t sBit64;

extern const char* hexTable[256];
extern const char* binTable[256];

static inline bit16 LB2(bit16 n) {
    bit16 t = 0;
    bit8* pt = (bit8*)&t;
    bit8* pn = (bit8*)&n;
    *(pt) = *(pn + 1);
    *(pt + 1) = *(pn);
    return t;
}
static inline bit32 LB4(bit32 n) {
    bit32 t = 0;
    bit8* pt = (bit8*)&t;
    bit8* pn = (bit8*)&n;
    *(pt) = *(pn + 3);
    *(pt + 1) = *(pn + 2);
    *(pt + 2) = *(pn + 1);
    *(pt + 3) = *(pn);
    return t;
}
static inline bit64 LB8(bit64 n) {
    bit64 t = 0;
    bit8* pt = (bit8*)&t;
    bit8* pn = (bit8*)&n;
    *(pt) = *(pn + 7);
    *(pt + 1) = *(pn + 6);
    *(pt + 2) = *(pn + 5);
    *(pt + 3) = *(pn + 4);
    *(pt + 4) = *(pn + 3);
    *(pt + 5) = *(pn + 2);
    *(pt + 6) = *(pn + 1);
    *(pt + 7) = *(pn);
    return t;
}

static inline bit32 crs(bit32 original, int bits) { //循环右移函数
	bits = bits % 32;
	return (original >> bits | original << 32 - bits);
};

static inline void toHex(const bit8* data, bit64 length, char* buff, bool reverse) {
    if (reverse) {
        for (bit64 i = 0; i < length; i++) {
            strncpy(buff + (length - i - 1) * 2, hexTable[*(data + i)], 2);
        }
        buff[length * 2] = '\0';
    }
    else {
        for (bit64 i = 0; i < length; i++) {
            strncpy(buff + i * 2, hexTable[*(data + i)], 2);
        }
        buff[length * 2] = '\0';
    }
};
static inline void toBin(const bit8* data, bit64 length, char* buff, bool reverse) {
    if (reverse) {
        for (bit64 i = 0; i < length; i++) {
            strncpy(buff + (length - i - 1) * 8, binTable[*(data + i)], 8);
        }
        buff[length * 8] = '\0';
    }
    else {
        for (bit64 i = 0; i < length; i++) {
            strncpy(buff + i * 8, binTable[*(data + i)], 8);
        }
        buff[length * 8] = '\0';
    }
};

void printHex(const bit8* data, bit64 length, bool reverse);
void printBin(const bit8* data, bit64 length, bool reverse);

#endif //BINARY_H
