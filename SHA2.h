#ifndef SHA2
#define SHA2
#include <iostream>
#include <fstream>
#include <iomanip>

#define SHA256 256;

typedef unsigned char Byte;
typedef unsigned int bit32;
typedef unsigned long long bit64;
struct hex2char {
	char a;
	char b;
};

extern bool isBigEnd;  //是否为大端环境

extern char result256[65];

extern bit32 h8[8];  //8个h常量
extern bit32 h64[64];  //64个常量表
extern bit32 temph8[8];  //保存临时h变量

extern bit32 chunk64[16];  //原始64个字节的字节块
extern bit32 chunk256[64];  //填充到256个字节后的字节块
 
bool isBigEnding();  //大小端判断函数
bit32 crs(bit32, int);  //循环右移函数
struct hex2char ByteToHexChar(Byte);  //单字节转换为两个十六进制字符
void h8ToStr();

bit32 func1(int);  //操作1
bit32 func2();  //操作2
void convert64to256();  //扩充64字节到256字节(将chunk64扩充到chunk256)
void Hash64();  //读取chunk256,计算64字节块的哈希，结果被保存到temph8
char* HashStr(const char*,  int = 256, bool = false, bit64 = 0, bit64 = 0);  //计算输入字符串的sha256值
char* HashFile(const char*, int = 256, bool = false);

void printHexFromArry(bit32*, bit64);


#endif
