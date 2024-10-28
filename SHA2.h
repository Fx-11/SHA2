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
extern char result256[65];  //保存最后的字符串格式结果
extern bit32 h8[8];  //8个h常量
extern const bit32 h64[64];  //64个常量表
extern bit32 temph8[8];  //临时保存计算中的h变量

extern bit32 chunk64[16];  //原始64个字节的字节块
extern bit32 chunk256[64];  //填充到256个字节后的字节块
 
bool isBigEndian();  //大小端判断函数
bit32 crs(bit32, int);  //循环右移函数
struct hex2char ByteToHexChar(Byte);  //单字节转换为两个十六进制字符
void h8ToStr();  //将最后保存的哈希值以十六进制字符串格式保存到result256,并刷新h8和temph8为初始常量值

void HashSingle64(bool = false);  //计算一个64字节块的哈希

char* HashStr(const char*,  int = 256, bool = false, bit64 = 0, bit64 = 0);  //计算输入字符串的sha256值(以默认编码方式)
char* HashFile(const char*, int = 256, bool = false);  //接受文件路径作为参数，计算文件哈希

void printHexFromArry(bit32*, bit64);  //调试用，用于打印计算中的字节块


#endif
