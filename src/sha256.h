#ifndef SHA256_H
#define SHA256_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "Binary.h"

#define SHA256 256


struct sha256Stat {
	bit8* data;  //指向接下来要计算的数据
	bit64 remainingCount;  // 还需要计算多少次（不包括末尾2个64字节），等于0时表示末尾除外的数据已经都计算完毕
	bit32 h[8];  // 8个哈希变量
	bit32 temph[8];  // 用于计算中的临时变量
	bit32 end128[32];  // 存储经预处理扩展后的数据
	char sha256[65];  // 存储最终的哈希结果（字符串形式)
	bit8 isCalc128; // 标记是否计算末尾128字节 0-不计算 1-前64字节 2-128字节
};


void* initialStat(bit8* data, bit64 length, int algorithm); // 初始化哈希状态，返回指向状态结构体的指针
void freeStat(void* statP);  // 释放哈希状态占用的内存
void updataStat(void* statP, bit8* data, bit64 length, int algorithm);
void preProcessStat(void* statP, bit64 totalLength, int algorithm);

void hash256(struct sha256Stat* sha256StatP);
void hashEnd256(struct sha256Stat* sha256StatP);
void autoHash256(struct sha256Stat* sha256StatP);

 
void hashStr(const char* str, char* buff, int algorithm);
void hashFile(const char* path, char* buff, int algorithm);
#endif

/*

									《《《所有函数不对内存进行检查》》》

关于代码原理，在此做下解释（以sha256为例）:
结构体保存指向要计算的数据的指针、当前哈希值、等信息
initialStat:
	初始化一个结构体并返回结构体指针，需要传入数据指针和当前数据长度进行初始化（传入的可以无意义，后续可以调用updateStat更新）
freeStat:
	计算结束后请务必释放结构体内存
updataStat：
	更新结构体中指向数据的指针和剩余计算次数
preProcessStat:
	传入整个数据的长度，处理末尾不满64字节的内容，一定要在哈希状态未开始计算时调用
hash256:
	对结构体进行一次sha256 64字节计算
hashEnd256:
	计算末尾2个64字节的哈希
autoHash256:
	根据结构体中剩余计算次数，自动计算完该次数，不包括末尾2个64字节

调用hashStr和hashFile进行直接计算时，请自己准备内存用来存放字符串形式的哈希结果
*/