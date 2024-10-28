#include "SHA2.h"

bool isBigEnd = isBigEndian();
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
bit32 h8[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

bit32 chunk64[16] = { 0 };  //保存需要计算的64字节块，每次计算前都会被更新，计算完不改变其内容，默认以4字节长度访问
bit32 chunk256[64] = { 0 };  //保存64字节块被填充到256字节后的结果，一样每次计算前更新，计算完内容不变，默认以4字节长度访问
bit32 temph8[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,  //保存每次计算后的中间哈希值，内容不变，计算时更新
0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};
char result256[65] = { '0' };  //以64字节字符串格式保存sha256计算完成后的结果(十六进制)


bool isBigEndian() {  // 判断当前运行环境是否为大端
	bit32 num = 0x00000011;
	Byte* p = (Byte*)&num;
	if (*p == 0x11) {
		return false;
	}
	else {
		return true;
	}
};

bit32 crs(bit32 original, int bits) {  // 将4字节original循环右移bits位并返回该值
	bits = bits % 32;
	bit32 temp = original;
	original = original >> bits;
	temp = temp << (32 - bits);
	return (original | temp);
}

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


void HashSingle64(bool isDebug) {
	if (isDebug) { printHexFromArry(chunk64, 16); }
	for (short i = 0; i < 16; i++) {  // 将64字节的消息扩充到256字节
		chunk256[i] = chunk64[i];  //前64字节直接复制
	}
	for (short j = 16; j < 64; j++) {  //循环填充4字节
		bit32 s0 = chunk256[j - 15];
		bit32 s1 = chunk256[j - 2];
		bit32 s2 = chunk256[j - 16];
		bit32 s3 = chunk256[j - 7];
		s0 = crs(s0, 7) ^ crs(s0, 18) ^ (s0 >> 3);
		s1 = crs(s1, 17) ^ crs(s1, 19) ^ (s1 >> 10);
		chunk256[j] = s0 + s1 + s2 + s3;
	}

	for (int i = 0; i < 64; i++) {  //64次循环，结果保存于全局temph8数组
		bit32 s1 = crs(temph8[4], 6) ^ crs(temph8[4], 11) ^ crs(temph8[4], 25);
		bit32 ch = (temph8[4] & temph8[5]) ^ (~temph8[4] & temph8[6]);
		bit32 cacheFunc1 = temph8[7] + s1 + ch + h64[i] + chunk256[i];
		bit32 s0 = crs(temph8[0], 2) ^ crs(temph8[0], 13) ^ crs(temph8[0], 22);
		bit32 maj = (temph8[0] & temph8[1]) ^ (temph8[0] & temph8[2]) ^ (temph8[1] & temph8[2]);

		temph8[3] += cacheFunc1;
		temph8[7] = cacheFunc1 + s0 + maj;
		bit32 temph7 = temph8[7];
		for (int h = 7; h > 0; h--) {
			temph8[h] = temph8[h - 1];
		}
		temph8[0] = temph7;
	}
	for (short i = 0; i < 8; i++) {  //处理h8哈希值数组
		h8[i] += temph8[i];
		temph8[i] = h8[i];
	}
}



void h8ToStr() { //将计算后的结果，即h8中存储的哈希值转换为字符串形式，并存储在result256中，,并刷新h8和temph8为初始常量值
	if (isBigEnd) {
		struct hex2char h = { 0, 0 };
		Byte* resultBegin = (Byte*)temph8;
		for (short bc = 0; bc < 32; bc++) {
			h = ByteToHexChar(*(resultBegin + bc));
			result256[bc * 2] = h.a;
			result256[bc * 2 + 1] = h.b;
		}
		result256[64] = '\0';
	}
	else {
		struct hex2char h = { 0, 0 }; 
		Byte* resultBegin = (Byte*)temph8;
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
	}
	h8[0] = 0x6a09e667;
	h8[1] = 0xbb67ae85;
	h8[2] = 0x3c6ef372;
	h8[3] = 0xa54ff53a;
	h8[4] = 0x510e527f;
	h8[5] = 0x9b05688c;
	h8[6] = 0x1f83d9ab;
	h8[7] = 0x5be0cd19;
	for (short i = 0; i < 8; i++) {
		temph8[i] = h8[i];
	}
}

char* HashStr(const char* message, int algorithm, bool isDebug, bit64 flaglengthb, bit64 flaglength) {  //这里的最后两个参数是用于计算文件哈希时调用本函数时使用的 
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

	if (isDebug) { std::cout << length << std::endl; }

	Byte* begin64 = (Byte*)chunk64;  //将chunk64按单字节操作
	bit32* beginMsg = (bit32*)message;

	if (isBigEnd) {  //在大端环境中按次序即可---------------------------------------------------大大大-----------------------------------------------
		for (bit64 operate = 0; operate < howMany64; operate++) {  //前面的整64字节块
			for (bit64 c = 0; c < 64; c++) {  //单个64字节块获取
				*(begin64 + c) = *(message + 64*operate+c);
			}
			HashSingle64(isDebug);

		}
		bit64 frontLength = 64 * howMany64;
		bit64 surplus = length - frontLength;
		if (surplus > 55 || surplus == 0) {  //剩余的字节放不下9个字节时
			if (surplus == 0) {
				*begin64 = 0x80;
				*(begin64 + 1) = 0x00;
				*(begin64 + 2) = 0x00;
				*(begin64 + 3) = 0x00;
				for (short i = 1; i < 14; i++) {
					chunk64[i] = 0x00000000;
				}

				Byte* len8 = (Byte*)&length8;
				for (bit64 l = 56; l < 64; l++) {
					*(begin64 + l) = *(len8 + l - 56);
				}

				HashSingle64(isDebug);

			}
			else {
				for (bit64 s = 0; s < surplus; s++) {  //单个64字节块获取
					*(begin64 + s) = *(message + frontLength + s);
				}
				*(begin64 + surplus) = 0x80;
				for (bit64 z = surplus + 1; z < 64; z++) {
					*(begin64 + surplus) = 0x00;
				}
				HashSingle64(isDebug);

				for (bit64 t = 0; t < 14; t++) {
					chunk64[t] = 0x00000000;
				}

				Byte* len8 = (Byte*)&length8;
				for (bit64 l = 56; l < 64; l++) {
					*(begin64 + l) = *(len8 + l - 56);
				}
				HashSingle64(isDebug);

			}
		}
		else {
			for (bit64 s = 0; s < surplus; s++) {  //单个64字节块获取
				*(begin64 + s) = *(message + frontLength + s);
			}
			*(begin64 + surplus) = 0x80;
			for (bit64 z = surplus + 1; z < 56; z++) {
				*(begin64 + surplus) = 0x00;
			}

			Byte* len8 = (Byte*)&length8;
			for (bit64 l = 56; l < 64; l++) {
				*(begin64 + l) = *(len8 + l - 56);
			}

			HashSingle64(isDebug);

		}
		h8ToStr();
		return result256;
	}  //------------------------------------------------------------------------端端端-----------------------------------------------------------
	else {  //在小端环境中需使每四个字节反转一下---------------------------------------------小小小----------------------------------------------------
		for (bit64 operate = 0; operate < howMany64; operate++) {  //前面的整数次64字节块，为0时不执行
			for (bit64 c = 0; c < 16; c++) {  //单个64字节块获取
				*(begin64 + c * 4 + 3) = *(message + 64 * operate + c * 4);  //小端系统中低位存放低位字节，因为需要以大端方式读取和处理字节块中的内容
				*(begin64 + c * 4 + 2) = *(message + 64 * operate + c * 4 + 1);  //所以在小端系统中需要保证低位地址中的内容被读取到高位
				*(begin64 + c * 4 + 1) = *(message + 64 * operate + c * 4 + 2);  //则往字节块中写入字节时需要将4字节中的高位数据放到低位地址存储
				*(begin64 + c * 4) = *(message + 64 * operate + c * 4 + 3);
			}

			HashSingle64(isDebug);

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

				HashSingle64(isDebug);

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

				if (isDebug) { printHexFromArry(chunk64, 16); }
				HashSingle64(isDebug);

				for (short i = 0; i < 14; i++) {  //最后一个字节块前面全部填充0x00
					chunk64[i] = 0x00000000;
				}
				bit32* length4 = (bit32*)&length8;  //填充后8个字节为message长度
				chunk64[15] = *length4;
				chunk64[14] = *(length4 + 1);

				HashSingle64(isDebug);

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

			HashSingle64(isDebug);

		}
		h8ToStr();
		return result256;
	}
}

char* HashFile(const char* path, int algorithm, bool isDebug) {
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

	if (!isBigEnd) {  //小端环境的情况下
		char buff[64] = { 0 };
		for (bit64 i = 0; i < howMany64; i++) {
			f.read(buff, 64);
			for (short i = 0; i < 16; i++) {
				*(begin64 + i * 4) = buff[i * 4 + 3];
				*(begin64 + i * 4 + 1) = buff[i * 4 + 2];
				*(begin64 + i * 4 + 2) = buff[i * 4 + 1];
				*(begin64 + i * 4 + 3) = buff[i * 4];
			}

			HashSingle64(isDebug);
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

			HashSingle64(isDebug);

			chunk64[0] = 0x80000000;
			for (short i = 1; i < 14; i++) {
				chunk64[i] = 0x00000000;
			}
			bit32* length4 = (bit32*)&length8;  //填充后8个字节为message长度
			chunk64[15] = *length4;
			chunk64[14] = *(length4 + 1);

			HashSingle64(isDebug);

			h8ToStr();
			return result256;
		}
		else {
			f.read(buff, surplus);
			f.close();
			buff[surplus] = '\0';
			return HashStr(buff, 256, isDebug, surplus, length);
		}
	}
}


void printHexFromArry(bit32* arry, bit64 length) {
	for (bit64 i = 0; i < length; i++) {
		std::cout << std::setw(8) << std::setfill('0') << std::uppercase << std::hex << *(arry + i) << " ";
	}
	std::cout << std::endl;
}

