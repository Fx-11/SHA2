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
extern char result256[65];  //保存最后的字符串格式结果
extern bit32 chunk64[16];
 
struct hex2char ByteToHexChar(Byte);  //单字节转换为两个十六进制字符
inline bit32 crs(bit32, int);  //循环右移函数
void HashSingle64();  //计算一个64字节块的哈希
char* h8ToStr();  //将最后保存的哈希值以十六进制字符串格式保存到result256,并刷新h8和temph8为初始常量值
char* HashStr(const char*,  int = 256, bit64 = 0, bit64 = 0);  //计算输入字符串的sha256值(以默认编码方式)
char* HashFile(char*, int = 256);  //接受文件路径作为参数，计算文件哈希


#endif
