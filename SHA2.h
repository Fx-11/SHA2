#ifndef SHA2
#define SHA2
#define _CRT_SECURE_NO_WARNINGS 1
#include <stdio.h>
#include <string.h>

#define SHA256 256;

typedef unsigned char Byte;
typedef unsigned int bit32;
typedef unsigned long long bit64;
struct hex2char {
	char a;
	char b;
};


inline bit32 crs(bit32 original, int bits) { //循环右移函数
	bits = bits % 32;
	return (original >> bits | original << 32 - bits);
};
char* HashStr(const char*,  int = 256, bit64 = 0, bit64 = 0);  //计算输入字符串的sha256值(以默认编码方式)
char* HashFile(char*, int = 256);  //接受文件路径作为参数，计算文件哈希


#endif
