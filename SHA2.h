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

extern char result256[65];

extern bit32 h8[8];  //8��h����
extern bit32 h64[64];  //64��������
extern bit32 temph8[8];  //������ʱh����

extern bit32 chunk64[16];  //ԭʼ64���ֽڵ��ֽڿ�
extern bit32 chunk256[64];  //��䵽256���ֽں���ֽڿ�
 
bool isBigEnding();  //��С���жϺ���
bit32 crs(bit32, int);  //ѭ�����ƺ���
struct hex2char ByteToHexChar(Byte);  //���ֽ�ת��Ϊ����ʮ�������ַ�
void h8ToStr();

bit32 func1(int);  //����1
bit32 func2();  //����2
void convert64to256();  //����64�ֽڵ�256�ֽ�(��chunk64���䵽chunk256)
void Hash64();  //��ȡchunk256,����64�ֽڿ�Ĺ�ϣ����������浽temph8
char* HashStr(const char*,  int = 256, bool = false, bit64 = 0, bit64 = 0);  //���������ַ�����sha256ֵ
char* HashFile(const char*, int = 256, bool = false);

void printHexFromArry(bit32*, bit64);


#endif
