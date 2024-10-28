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

extern bool isBigEnd;  //�Ƿ�Ϊ��˻���
extern char result256[65];  //���������ַ�����ʽ���
extern bit32 h8[8];  //8��h����
extern const bit32 h64[64];  //64��������
extern bit32 temph8[8];  //��ʱ��������е�h����

extern bit32 chunk64[16];  //ԭʼ64���ֽڵ��ֽڿ�
extern bit32 chunk256[64];  //��䵽256���ֽں���ֽڿ�
 
bool isBigEndian();  //��С���жϺ���
bit32 crs(bit32, int);  //ѭ�����ƺ���
struct hex2char ByteToHexChar(Byte);  //���ֽ�ת��Ϊ����ʮ�������ַ�
void h8ToStr();  //����󱣴�Ĺ�ϣֵ��ʮ�������ַ�����ʽ���浽result256,��ˢ��h8��temph8Ϊ��ʼ����ֵ

void HashSingle64(bool = false);  //����һ��64�ֽڿ�Ĺ�ϣ

char* HashStr(const char*,  int = 256, bool = false, bit64 = 0, bit64 = 0);  //���������ַ�����sha256ֵ(��Ĭ�ϱ��뷽ʽ)
char* HashFile(const char*, int = 256, bool = false);  //�����ļ�·����Ϊ�����������ļ���ϣ

void printHexFromArry(bit32*, bit64);  //�����ã����ڴ�ӡ�����е��ֽڿ�


#endif
