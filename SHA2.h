#ifndef SHA2
#define SHA2
#define _CRT_SECURE_NO_WARNINGS 1
#include <stdio.h>


#define SHA256 256;

typedef unsigned char Byte;
typedef unsigned int bit32;
typedef unsigned long long bit64;
struct hex2char {
	char a;
	char b;
};

extern bit64 count;
extern char result256[65];  //���������ַ�����ʽ���
extern bit32 chunk64[16];
 
struct hex2char ByteToHexChar(Byte);  //���ֽ�ת��Ϊ����ʮ�������ַ�
inline bit32 crs(bit32, int);  //ѭ�����ƺ���
void HashSingle64();  //����һ��64�ֽڿ�Ĺ�ϣ
char* h8ToStr();  //����󱣴�Ĺ�ϣֵ��ʮ�������ַ�����ʽ���浽result256,��ˢ��h8��temph8Ϊ��ʼ����ֵ
char* HashStr(const char*,  int = 256, bit64 = 0, bit64 = 0);  //���������ַ�����sha256ֵ(��Ĭ�ϱ��뷽ʽ)
char* HashFile(char*, int = 256);  //�����ļ�·����Ϊ�����������ļ���ϣ


#endif
