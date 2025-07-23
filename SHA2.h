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


inline bit32 crs(bit32 original, int bits) { //ѭ�����ƺ���
	bits = bits % 32;
	return (original >> bits | original << 32 - bits);
};
char* HashStr(const char*,  int = 256, bit64 = 0, bit64 = 0);  //���������ַ�����sha256ֵ(��Ĭ�ϱ��뷽ʽ)
char* HashFile(char*, int = 256);  //�����ļ�·����Ϊ�����������ļ���ϣ


#endif
