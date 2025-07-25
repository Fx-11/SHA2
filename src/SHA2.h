#ifndef SHA2
#define SHA2
#include <string>
#include "SHA256.h"


std::string HashStr(std::string str, int algorithm=256);
std::string HashFile(std::string path, int algorithm = 256);


#endif

// 字符串和文件哈希的C++接口，更加便捷，无需自行管理内存
