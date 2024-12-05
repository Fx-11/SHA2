# SHA2
SHA2 hash algorithm implemented in C++

使用C++实现的Sha256哈希算法，其中的"HashStr()"和"HashFile()"可分别计算字符串(默认编码格式)和一个文件的哈希值
***example:***
````
#include "SHA2.h"
#include <iostream>


int main() {
	char aString[] = "Hello World!";
	std::cout << HashStr(aString) << std::endl;  // 7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069

	char aPath[] = "D:\\example.png";
	std::cout << HashFile(aPath) << std::endl;  // 9adf3eb60b463a62251cbc7a7e9e3be5e3f50b602b431322c982bec4a9027662

	return 0;
}
````
***

那个名为"hash.py"的Python脚本可以随机生成一个测试字符串(还得是Python)

### 关于性能优化

(水平暂时有限，仅供学习交流)
目前在不开启编译器优化的情况下，1.7GB测试文件已经从最初的70s优化到了15s；
开启O2优化，从最初的7s左右优化到目前的5.2s左右（CPU为R9-7945HX以5.2GHz运行）
目前先这样了，什么时候有空再继续优化性能或做其他算法
