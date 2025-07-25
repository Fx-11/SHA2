# SHA2

---

## *sha256*
*使用C语言实现的SHA-256哈希算法，支持字符串和文件的哈希计算，并提供增量哈希接口处理大数据*
#### 性能参考：
条件：Windows11  AMD R9-7945HX(5.2GHz)   内存5.2Ghz双通道  g++O3编译
未优化版：约340MB/s
优化版：优化中...

---
#### 基础函数(C):
- initialStat - 初始化哈希状态结构体
- freeStat - 释放状态结构体内存
- updataStat - 更新待哈希数据指针
- preProcessStat - 预处理最后不完整的64字节数据块
- hash256 - 计算单个64字节数据块
- hashEnd256 - 计算末尾填充的数据块
- autoHash256 - 自动计算所有完整数据块
#### 便捷函数:
- hashStr(C)/HashStr(C++) - 直接计算字符串的SHA-256哈希值
- hashFile(C)/HashFile(C++) - 计算文件的SHA-256哈希值

---
#### *example:*
***C++:***
```
#include <iostream>
#include <string>
#include "SHA2.h" //C++只需包含SHA2.h即可

int main() {
	std::cout << HashStr("Hello World") << std::endl;
	std::cout << HashFile("test.bin") << std::endl;

	return 0;
}
```
***C:***
```
#include <stdio.h>
#include "sha256.h"

int main() {
	char hashVal[65]; // 自行准备内存用于存放字符串形式的哈希值
	const char* testData = "ABCDEF";
	bit64 length = 6;


	hashStr("Hi sha256", hashVal, SHA256); // 字符串哈希
	hashFile("anime.mkv", hashVal, SHA256); 	// 文件哈希


	struct sha256Stat* state = (struct sha256Stat*)initialStat((bit8*)testData, length, SHA256);// 增量哈希, 结果存于结构体中的sha256数组，释放结构体内存前自行取出
	updataStat(state, (bit8*)testData, length, SHA256);
	preProcessStat(state, length, SHA256);
	autoHash256(state);
	hashEnd256(state);
	freeStat(state);
	//所有函数不进行内存检查，请自行管理内存

	return 0;
}
```

---
## 其他哈希算法实现：
有空再写...