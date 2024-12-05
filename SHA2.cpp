#include "SHA2.h"

bit64 count = 0;

const bit32 h64[64] = { 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};
bit32 h0 = 0x6a09e667, temph0 = h0;
bit32 h1 = 0xbb67ae85, temph1 = h1;
bit32 h2 = 0x3c6ef372, temph2 = h2;
bit32 h3 = 0xa54ff53a, temph3 = h3;
bit32 h4 = 0x510e527f, temph4 = h4;
bit32 h5 = 0x9b05688c, temph5 = h5;
bit32 h6 = 0x1f83d9ab, temph6 = h6;
bit32 h7 = 0x5be0cd19, temph7 = h7;
bit32 chunk64[16] = { 0 };  //保存需要计算的64字节块，每次计算前都会被更新，计算完不改变其内容，默认以4字节长度访问
bit32 chunk256[64] = { 0 };  //保存64字节块被填充到256字节后的结果，一样每次计算前更新，计算完内容不变，默认以4字节长度访问
bit32 h8[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
char result256[65] = { '0' };  //以64字节字符串格式保存sha256计算完成后的结果(十六进制)

bit32 s0;
bit32 s1;
bit32 cacheFunc1;
short ji;

struct hex2char ByteToHexChar(Byte num) {  // 将Byte类型转换为两个十六进制字符，返回一个保存有两个字符的结构体
	Byte front = num >> 4;
	Byte back = num << 4;
	back = back >> 4;
	struct hex2char temp;
	if (front < 10) {
		temp.a = (char)(front + 48);
	}
	else {
		temp.a = (char)(front + 87);
	}
	if (back < 10) {
		temp.b = (char)(back + 48);
	}
	else {
		temp.b = (char)(back + 87);
	}
	return temp;
}
char* h8ToStr() { //将计算后的结果，即h8中存储的哈希值转换为字符串形式，并存储在result256中，,并刷新h8和temph8为初始常量值
	struct hex2char h = { 0, 0 };
	h8[0] = h0;
	h8[1] = h1;
	h8[2] = h2;
	h8[3] = h3;
	h8[4] = h4;
	h8[5] = h5;
	h8[6] = h6;
	h8[7] = h7;
	Byte* resultBegin = (Byte*)h8;
	for (short bc = 0; bc < 8; bc++) {
		h = ByteToHexChar(*(resultBegin + bc * 4 + 3));
		result256[bc * 8] = h.a;
		result256[bc * 8 + 1] = h.b;
		h = ByteToHexChar(*(resultBegin + bc * 4 + 2));
		result256[bc * 8 + 2] = h.a;
		result256[bc * 8 + 3] = h.b;
		h = ByteToHexChar(*(resultBegin + bc * 4 + 1));
		result256[bc * 8 + 4] = h.a;
		result256[bc * 8 + 5] = h.b;
		h = ByteToHexChar(*(resultBegin + bc * 4));
		result256[bc * 8 + 6] = h.a;
		result256[bc * 8 + 7] = h.b;
	}
	result256[64] = '\0';
	h0 = temph0 = 0x6a09e667;
	h1 = temph1 = 0xbb67ae85;
	h2 = temph2 = 0x3c6ef372;
	h3 = temph3 = 0xa54ff53a;
	h4 = temph4 = 0x510e527f;
	h5 = temph5 = 0x9b05688c;
	h6 = temph6 = 0x1f83d9ab;
	h7 = temph7 = 0x5be0cd19;
	return result256;
}
inline bit32 crs(bit32 original, int bits) {  // 将4字节original循环右移bits位并返回该值
	bits = bits % 32;
	return (original>>bits | original<<32-bits);
}


void HashSingle64() {
	chunk256[0] = chunk64[0]; // 将64字节的消息扩充到256字节
	chunk256[1] = chunk64[1]; // 前64字节直接复制
	chunk256[2] = chunk64[2]; // 循环展开
	chunk256[3] = chunk64[3];
	chunk256[4] = chunk64[4];
	chunk256[5] = chunk64[5];
	chunk256[6] = chunk64[6];
	chunk256[7] = chunk64[7];
	chunk256[8] = chunk64[8];
	chunk256[9] = chunk64[9];
	chunk256[10] = chunk64[10];
	chunk256[11] = chunk64[11];
	chunk256[12] = chunk64[12];
	chunk256[13] = chunk64[13];
	chunk256[14] = chunk64[14];
	chunk256[15] = chunk64[15];
	for (short j = 16; j < 64; j++) {  //循环填充4字节
		s0 = chunk256[j - 15];
		s1 = chunk256[j - 2];
		s0 = ((s0 >> 7) | (s0 << 25)) ^ ((s0 >> 18) | (s0 << 14)) ^ (s0 >> 3);
		s1 = ((s1 >> 17) | (s1 << 15)) ^ ((s1 >> 19) | (s1 << 13)) ^ (s1 >> 10);
		chunk256[j] = s0 + s1 + chunk256[j - 16] + chunk256[j - 7];
	}
	//以上为16个四字节扩充到64个四字节的过程
	//以下为处理计算h0-h7值的过程
	for (short i = 0; i < 8; i++) {
		ji = i * 8;
		//                7          4         4            4          4            4          4              4      5       4      6
		cacheFunc1 = temph7 + ((temph4>>6|temph4<<26)^(temph4>>11|temph4<<21)^(temph4>>25|temph4<<7)) + (temph4&temph5^~temph4&temph6) + h64[ji] + chunk256[ji];
		temph3 += cacheFunc1;
		//   7                       0         0            0          0            0          0               0      1      0      2      1      2
		temph7 = cacheFunc1 + ((temph0>>2|temph0<<30)^(temph0>>13|temph0<<19)^(temph0>>22|temph0<<10)) + (temph0&temph1^temph0&temph2^temph1&temph2);
		//                6          3         3            3          3            3          3              3      4       3      5
		cacheFunc1 = temph6 + ((temph3>>6|temph3<<26)^(temph3>>11|temph3<<21)^(temph3>>25|temph3<<7)) + (temph3&temph4^~temph3&temph5) + h64[ji+1] + chunk256[ji+1];
		temph2 += cacheFunc1;
		//   6                       7         7            7          7            7          7               7      0      7      1      0      1
		temph6 = cacheFunc1 + ((temph7>>2|temph7<<30)^(temph7>>13|temph7<<19)^(temph7>>22|temph7<<10)) + (temph7&temph0^temph7&temph1^temph0&temph1);
		//                5          2         2            2          2            2          2              2      3       2      4
		cacheFunc1 = temph5 + ((temph2>>6|temph2<<26)^(temph2>>11|temph2<<21)^(temph2>>25|temph2<<7)) + (temph2&temph3^~temph2&temph4) + h64[ji+2] + chunk256[ji+2];
		temph1 += cacheFunc1;
		//   5                       6         6            6          6            6          6               6      7      6      0      7      0
		temph5 = cacheFunc1 + ((temph6>>2|temph6<<30)^(temph6>>13|temph6<<19)^(temph6>>22|temph6<<10)) + (temph6&temph7^temph6&temph0^temph7&temph0);
		//                4          1         1            1          1            1          1              1      2       1      3
		cacheFunc1 = temph4 + ((temph1>>6|temph1<<26)^(temph1>>11|temph1<<21)^(temph1>>25|temph1<<7)) + (temph1&temph2^~temph1&temph3) + h64[ji+3] + chunk256[ji+3];
		temph0 += cacheFunc1;
		//   4                       5         5            5          5            5          5               5      6      5      7      6      7
		temph4 = cacheFunc1 + ((temph5>>2|temph5<<30)^(temph5>>13|temph5<<19)^(temph5>>22|temph5<<10)) + (temph5&temph6^temph5&temph7^temph6&temph7);
		//                3          0         0            0          0            0          0              0      1       0      2
		cacheFunc1 = temph3 + ((temph0>>6|temph0<<26)^(temph0>>11|temph0<<21)^(temph0>>25|temph0<<7)) + (temph0&temph1^~temph0&temph2) + h64[ji+4] + chunk256[ji+4];
		temph7 += cacheFunc1;
		//   3                       4         4            4          4            4          4               4      5      4      6      5      6
		temph3 = cacheFunc1 + ((temph4>>2|temph4<<30)^(temph4>>13|temph4<<19)^(temph4>>22|temph4<<10)) + (temph4&temph5^temph4&temph6^temph5&temph6);
		//                2          7         7            7          7            7          7              7      0       7      1
		cacheFunc1 = temph2 + ((temph7>>6|temph7<<26)^(temph7>>11|temph7<<21)^(temph7>>25|temph7<<7)) + (temph7&temph0^~temph7&temph1) + h64[ji+5] + chunk256[ji+5];
		temph6 += cacheFunc1;
		//   2                       3         3            3          3            3          3               3      4      3      5      4      5
		temph2 = cacheFunc1 + ((temph3>>2|temph3<<30)^(temph3>>13|temph3<<19)^(temph3>>22|temph3<<10)) + (temph3&temph4^temph3&temph5^temph4&temph5);
		//                1          6         6            6          6            6          6              6             6       0
		cacheFunc1 = temph1 + ((temph6>>6|temph6<<26)^(temph6>>11|temph6<<21)^(temph6>>25|temph6<<7)) + (temph6&temph7^~temph6&temph0) + h64[ji+6] + chunk256[ji+6];
		temph5 += cacheFunc1;
		//   1                       2         2            2          2            2          2               2      3      2      4      3      4
		temph1 = cacheFunc1 + ((temph2>>2|temph2<<30)^(temph2>>13|temph2<<19)^(temph2>>22|temph2<<10)) + (temph2&temph3^temph2&temph4^temph3&temph4);
		//                0          5         5            5          5            5          5              5      6       5      7
		cacheFunc1 = temph0 + ((temph5>>6|temph5<<26)^(temph5>>11|temph5<<21)^(temph5>>25|temph5<<7)) + (temph5&temph6^~temph5&temph7) + h64[ji+7] + chunk256[ji+7];
		temph4 += cacheFunc1;
		//   0                       1         1            1          1            1          1               1      2      1      3      2      3
		temph0 = cacheFunc1 + ((temph1>>2|temph1<<30)^(temph1>>13|temph1<<19)^(temph1>>22|temph1<<10)) + (temph1&temph2^temph1&temph3^temph2&temph3);
	}
	h0 += temph0;
	h1 += temph1;
	h2 += temph2;
	h3 += temph3;
	h4 += temph4;
	h5 += temph5;
	h6 += temph6;
	h7 += temph7;
	temph0 = h0;
	temph1 = h1;
	temph2 = h2;
	temph3 = h3;
	temph4 = h4;
	temph5 = h5;
	temph6 = h6;
	temph7 = h7;
}

char* HashStr(const char* message, int algorithm, bit64 flaglengthb, bit64 flaglength) {  //这里的最后两个参数是用于计算文件哈希时调用本函数时使用的 
	bit64 length = 0;               //isDebug为true时会在执行过程中打印出每个字节块
	bit64 length8 = 0;              
	bit64 howMany64 = 0;  //有多少个整64字节块
	if (flaglengthb == 0) {
		while (true) {
			if (*(message + length) != '\0') {
				length += 1;
				continue;
			}
			break;
		}
		howMany64 = length >> 6;
		length8 = length * 8;
	}
	else {
		length = flaglengthb;
		length8 = flaglength * 8;
	}


	Byte* begin64 = (Byte*)chunk64;  //将chunk64按单字节操作
	bit32* beginMsg = (bit32*)message;


	//在小端环境中需使每四个字节反转一下---------------------------------------------小小小----------------------------------------------------
	for (bit64 operate = 0; operate < howMany64; operate++) {  //前面的整数次64字节块，为0时不执行
		for (bit64 c = 0; c < 16; c++) {  //单个64字节块获取
			*(begin64 + c * 4 + 3) = *(message + 64 * operate + c * 4);  //小端系统中低位存放低位字节，因为需要以大端方式读取和处理字节块中的内容
			*(begin64 + c * 4 + 2) = *(message + 64 * operate + c * 4 + 1);  //所以在小端系统中需要保证低位地址中的内容被读取到高位
			*(begin64 + c * 4 + 1) = *(message + 64 * operate + c * 4 + 2);  //则往字节块中写入字节时需要将4字节中的高位数据放到低位地址存储
			*(begin64 + c * 4) = *(message + 64 * operate + c * 4 + 3);
		}

		HashSingle64();

	}
	bit64 frontLength = 64 * howMany64;  //获取前面n个64字节的总长度，用于提供基础偏置读取原始消息中的后面不足64字节的内容
	bit64 surplus = length - frontLength;  //计算后面不足64字节部分的长度
	bit64 surplus4 = surplus >> 2;  //因为在小端系统中，需要每四个字节四个字节的处理，所以获取一共有多少个整4字节
	bit64 surplusb = surplus - 4 * surplus4;  //nn个四字节后还有多少个字节

	if (surplus > 55 || surplus == 0) {  //剩余的字节放不下9个字节时(n==0时即整个message为64字节的整数倍，此时只需填充0x80和8字节长度)

		if (surplus == 0) {  //长度为64字节整数倍时，最后一个64字节块被填充0x8000000 0000...0000 length(8 bits)
			chunk64[0] = 0x80000000;
			for (short i = 1; i < 14; i++) {
				chunk64[i] = 0x00000000;
			}
			bit32* length4 = (bit32*)&length8;  //填充后8个字节为message长度
			chunk64[15] = *length4;
			chunk64[14] = *(length4 + 1);

			HashSingle64();

		}
		else {  //此为55 < surplus < 64的情况
			for (bit64 s = 0; s < surplus4; s++) {  //单个64字节块获取
				*(begin64 + s * 4 + 3) = *(message + frontLength + s * 4);
				*(begin64 + s * 4 + 2) = *(message + frontLength + s * 4 + 1);
				*(begin64 + s * 4 + 1) = *(message + frontLength + s * 4 + 2);
				*(begin64 + s * 4) = *(message + frontLength + s * 4 + 3);
			}
			for (bit64 b = 0; b < surplusb; b++) {  //填充剩余的非4字节整的数据，及0x80和0x00
				*(begin64 + surplus4 * 4 + 3 - b) = *(message + length - surplusb + b);
			}
			*(begin64 + surplus4 * 4 + 3 - surplusb) = 0x80;
			for (bit64 bl = 0; bl < 3 - surplusb; bl++) {
				*(begin64 + surplus4 * 4 + 2 - surplusb - bl) = 0x00;
			}
			for (bit64 z = (surplus4 + 1)*4; z < 64; z++) {
				*(begin64 + z) = 0x00;
			}

			HashSingle64();

			for (short i = 0; i < 14; i++) {  //最后一个字节块前面全部填充0x00
				chunk64[i] = 0x00000000;
			}
			bit32* length4 = (bit32*)&length8;  //填充后8个字节为message长度
			chunk64[15] = *length4;
			chunk64[14] = *(length4 + 1);

			HashSingle64();

		}
	}
	else {  //此为0 < length < 55的情况
		for (bit64 s = 0; s < surplus4; s++) {  //填充前面4*surplus4字节
			*(begin64 + s * 4 + 3) = *(message + frontLength + s * 4);
			*(begin64 + s * 4 + 2) = *(message + frontLength + s * 4 + 1);
			*(begin64 + s * 4 + 1) = *(message + frontLength + s * 4 + 2);
			*(begin64 + s * 4) = *(message + frontLength + s * 4 + 3);
		}
		for (bit64 b = 0; b < surplusb; b++) {  //填充剩下的不足4字节的内容和0x00
			*(begin64 + surplus4 * 4 + 3 - b) = *(message + length - surplusb + b);
		}
		*(begin64 + surplus4 * 4 + 3 - surplusb) = 0x80;
		for (bit64 bl = 0; bl < 3 - surplusb; bl++) {
			*(begin64 + surplus4 * 4 + 2 - surplusb - bl) = 0x00;
		}
		for (bit64 z = 4*(surplus4 + 1); z < 56; z++) {  //剩下的填充0x00
			*(begin64 + z) = 0x00;
		}

		bit32* length4 = (bit32*)&length8;  //填充后8个字节为message长度
		chunk64[15] = *length4;
		chunk64[14] = *(length4 + 1);

		HashSingle64();

	}
	h8ToStr();
	return result256;
}


char* HashFile(std::string path, int algorithm) {
	std::fstream f(path, std::ios::in | std::ios::binary | std::ios::ate);
	std::streampos endP = f.tellg();  //获取文件长度
	f.seekg(std::ios::beg);
	//if (endP >> 61 != 0) {
	//	std::cerr << "file is too big";
	//	return nullptr;
	//}
	bit64 length = endP;  //文件总长度(字节)
	bit64 howMany64 = length >> 6;  //64字节块个数
	bit64 length8 = length << 3;  //总位数(需要填充的长度信息)
	bit64 surplus = length - 64 * howMany64;  //最后不足64字节字节数
	if (surplus == 0) { howMany64--; }
	Byte* begin64 = (Byte*)chunk64;

	char buff[64] = { 0 };
	for (bit64 i = 0; i < howMany64; i++) {
		f.read(buff, 64);
		for (short i = 0; i < 16; i++) {
			*(begin64 + i * 4) = buff[i * 4 + 3];
			*(begin64 + i * 4 + 1) = buff[i * 4 + 2];
			*(begin64 + i * 4 + 2) = buff[i * 4 + 1];
			*(begin64 + i * 4 + 3) = buff[i * 4];
		}

		HashSingle64();
	}
	if (surplus == 0) {
		f.read(buff, 64);
		f.close();
		for (short i = 0; i < 16; i++) {
			*(begin64 + i * 4) = buff[i * 4 + 3];
			*(begin64 + i * 4 + 1) = buff[i * 4 + 2];
			*(begin64 + i * 4 + 2) = buff[i * 4 + 1];
			*(begin64 + i * 4 + 3) = buff[i * 4];
		}

		HashSingle64();

		chunk64[0] = 0x80000000;
		for (short i = 1; i < 14; i++) {
			chunk64[i] = 0x00000000;
		}
		bit32* length4 = (bit32*)&length8;  //填充后8个字节为message长度
		chunk64[15] = *length4;
		chunk64[14] = *(length4 + 1);

		HashSingle64();

		h8ToStr();
		return result256;
	}
	else {
		f.read(buff, surplus);
		f.close();
		buff[surplus] = '\0';
		return HashStr(buff, 256, surplus, length);
	}
}

