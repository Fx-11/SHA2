#ifndef SHA256_H
#define SHA256_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "Binary.h"

#define SHA256 256


struct sha256Stat {
	bit8* data;  //ָ�������Ҫ���������
	bit64 remainingCount;  // ����Ҫ������ٴΣ�������ĩβ2��64�ֽڣ�������0ʱ��ʾĩβ����������Ѿ����������
	bit32 h[8];  // 8����ϣ����
	bit32 temph[8];  // ���ڼ����е���ʱ����
	bit32 end128[32];  // �洢��Ԥ������չ�������
	char sha256[65];  // �洢���յĹ�ϣ������ַ�����ʽ)
	bit8 isCalc128; // ����Ƿ����ĩβ128�ֽ� 0-������ 1-ǰ64�ֽ� 2-128�ֽ�
};


void* initialStat(bit8* data, bit64 length, int algorithm); // ��ʼ����ϣ״̬������ָ��״̬�ṹ���ָ��
void freeStat(void* statP);  // �ͷŹ�ϣ״̬ռ�õ��ڴ�
void updataStat(void* statP, bit8* data, bit64 length, int algorithm);
void preProcessStat(void* statP, bit64 totalLength, int algorithm);

void hash256(struct sha256Stat* sha256StatP);
void hashEnd256(struct sha256Stat* sha256StatP);
void autoHash256(struct sha256Stat* sha256StatP);

 
void hashStr(const char* str, char* buff, int algorithm);
void hashFile(const char* path, char* buff, int algorithm);
#endif

/*

									���������к��������ڴ���м�顷����

���ڴ���ԭ���ڴ����½��ͣ���sha256Ϊ����:
�ṹ�屣��ָ��Ҫ��������ݵ�ָ�롢��ǰ��ϣֵ������Ϣ
initialStat:
	��ʼ��һ���ṹ�岢���ؽṹ��ָ�룬��Ҫ��������ָ��͵�ǰ���ݳ��Ƚ��г�ʼ��������Ŀ��������壬�������Ե���updateStat���£�
freeStat:
	���������������ͷŽṹ���ڴ�
updataStat��
	���½ṹ����ָ�����ݵ�ָ���ʣ��������
preProcessStat:
	�����������ݵĳ��ȣ�����ĩβ����64�ֽڵ����ݣ�һ��Ҫ�ڹ�ϣ״̬δ��ʼ����ʱ����
hash256:
	�Խṹ�����һ��sha256 64�ֽڼ���
hashEnd256:
	����ĩβ2��64�ֽڵĹ�ϣ
autoHash256:
	���ݽṹ����ʣ�����������Զ�������ô�����������ĩβ2��64�ֽ�

����hashStr��hashFile����ֱ�Ӽ���ʱ�����Լ�׼���ڴ���������ַ�����ʽ�Ĺ�ϣ���
*/