#ifndef SHA2
#define SHA2
#include <string>
#include "SHA256.h"


std::string HashStr(std::string str, int algorithm=256);
std::string HashFile(std::string path, int algorithm = 256);


#endif

// �ַ������ļ���ϣ��C++�ӿڣ����ӱ�ݣ��������й����ڴ�
