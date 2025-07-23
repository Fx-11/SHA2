#include "SHA2.h"

bit64 count = 0;

const bit32 h64[64] = {
0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
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
bit32 h[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
bit32 temph[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };


bit32 chunk64[16] = { 0 };  //������Ҫ�����64�ֽڿ飬ÿ�μ���ǰ���ᱻ���£������겻�ı������ݣ�Ĭ����4�ֽڳ��ȷ���
bit32 chunk256[64] = { 0 };  //����64�ֽڿ鱻��䵽256�ֽں�Ľ����һ��ÿ�μ���ǰ���£����������ݲ��䣬Ĭ����4�ֽڳ��ȷ���
char result256[65] = { '0' };  //��64�ֽ��ַ�����ʽ����sha256������ɺ�Ľ��(ʮ������)

bit32 s0;
bit32 s1;
bit32 cacheFunc1;
short ji;

struct hex2char ByteToHexChar(Byte num) {  // ��Byte����ת��Ϊ����ʮ�������ַ�������һ�������������ַ��Ľṹ��
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
char* h8ToStr() { //�������Ľ������h8�д洢�Ĺ�ϣֵת��Ϊ�ַ�����ʽ�����洢��result256�У�,��ˢ��h8��temph8Ϊ��ʼ����ֵ
	struct hex2char hexc = { 0, 0 };
	Byte* resultBegin = (Byte*)h;
	for (short bc = 0; bc < 8; bc++) {
		hexc = ByteToHexChar(*(resultBegin + bc * 4 + 3));
		result256[bc * 8] = hexc.a;
		result256[bc * 8 + 1] = hexc.b;
		hexc = ByteToHexChar(*(resultBegin + bc * 4 + 2));
		result256[bc * 8 + 2] = hexc.a;
		result256[bc * 8 + 3] = hexc.b;
		hexc = ByteToHexChar(*(resultBegin + bc * 4 + 1));
		result256[bc * 8 + 4] = hexc.a;
		result256[bc * 8 + 5] = hexc.b;
		hexc = ByteToHexChar(*(resultBegin + bc * 4));
		result256[bc * 8 + 6] = hexc.a;
		result256[bc * 8 + 7] = hexc.b;
	}
	result256[64] = '\0';
	h[0] = temph[0] = 0x6a09e667;
	h[1] = temph[1] = 0xbb67ae85;
	h[2] = temph[2] = 0x3c6ef372;
	h[3] = temph[3] = 0xa54ff53a;
	h[4] = temph[4] = 0x510e527f;
	h[5] = temph[5] = 0x9b05688c;
	h[6] = temph[6] = 0x1f83d9ab;
	h[7] = temph[7] = 0x5be0cd19;
	return result256;
}

void HashSingle64() {
	memcpy(chunk256, chunk64, 64);// ��64�ֽڵ���Ϣ���䵽256�ֽ�, ǰ64�ֽ�ֱ�Ӹ���
	for (short j = 16; j < 64; j++) {  //ѭ�����4�ֽ�
		s0 = chunk256[j - 15];
		s1 = chunk256[j - 2];
		s0 = ((s0 >> 7) | (s0 << 25)) ^ ((s0 >> 18) | (s0 << 14)) ^ (s0 >> 3);
		s1 = ((s1 >> 17) | (s1 << 15)) ^ ((s1 >> 19) | (s1 << 13)) ^ (s1 >> 10);
		chunk256[j] = s0 + s1 + chunk256[j - 16] + chunk256[j - 7];
	}
	//����Ϊ16�����ֽ����䵽64�����ֽڵĹ���
	//����Ϊ�������h[0]-h[7]ֵ�Ĺ���
	for (short i = 0; i < 8; i++) {
		ji = i * 8;
		//                7          4         4            4          4            4          4              4      5       4      6
		cacheFunc1 = temph[7] + ((temph[4]>>6|temph[4]<<26)^(temph[4]>>11|temph[4]<<21)^(temph[4]>>25|temph[4]<<7)) + (temph[4]&temph[5]^~temph[4]&temph[6]) + h64[ji] + chunk256[ji];
		temph[3] += cacheFunc1;
		//   7                       0         0            0          0            0          0               0      1      0      2      1      2
		temph[7] = cacheFunc1 + ((temph[0]>>2|temph[0]<<30)^(temph[0]>>13|temph[0]<<19)^(temph[0]>>22|temph[0]<<10)) + (temph[0]&temph[1]^temph[0]&temph[2]^temph[1]&temph[2]);
		//                6          3         3            3          3            3          3              3      4       3      5
		cacheFunc1 = temph[6] + ((temph[3]>>6|temph[3]<<26)^(temph[3]>>11|temph[3]<<21)^(temph[3]>>25|temph[3]<<7)) + (temph[3]&temph[4]^~temph[3]&temph[5]) + h64[ji+1] + chunk256[ji+1];
		temph[2] += cacheFunc1;
		//   6                       7         7            7          7            7          7               7      0      7      1      0      1
		temph[6] = cacheFunc1 + ((temph[7]>>2|temph[7]<<30)^(temph[7]>>13|temph[7]<<19)^(temph[7]>>22|temph[7]<<10)) + (temph[7]&temph[0]^temph[7]&temph[1]^temph[0]&temph[1]);
		//                5          2         2            2          2            2          2              2      3       2      4
		cacheFunc1 = temph[5] + ((temph[2]>>6|temph[2]<<26)^(temph[2]>>11|temph[2]<<21)^(temph[2]>>25|temph[2]<<7)) + (temph[2]&temph[3]^~temph[2]&temph[4]) + h64[ji+2] + chunk256[ji+2];
		temph[1] += cacheFunc1;
		//   5                       6         6            6          6            6          6               6      7      6      0      7      0
		temph[5] = cacheFunc1 + ((temph[6]>>2|temph[6]<<30)^(temph[6]>>13|temph[6]<<19)^(temph[6]>>22|temph[6]<<10)) + (temph[6]&temph[7]^temph[6]&temph[0]^temph[7]&temph[0]);
		//                4          1         1            1          1            1          1              1      2       1      3
		cacheFunc1 = temph[4] + ((temph[1]>>6|temph[1]<<26)^(temph[1]>>11|temph[1]<<21)^(temph[1]>>25|temph[1]<<7)) + (temph[1]&temph[2]^~temph[1]&temph[3]) + h64[ji+3] + chunk256[ji+3];
		temph[0] += cacheFunc1;
		//   4                       5         5            5          5            5          5               5      6      5      7      6      7
		temph[4] = cacheFunc1 + ((temph[5]>>2|temph[5]<<30)^(temph[5]>>13|temph[5]<<19)^(temph[5]>>22|temph[5]<<10)) + (temph[5]&temph[6]^temph[5]&temph[7]^temph[6]&temph[7]);
		//                3          0         0            0          0            0          0              0      1       0      2
		cacheFunc1 = temph[3] + ((temph[0]>>6|temph[0]<<26)^(temph[0]>>11|temph[0]<<21)^(temph[0]>>25|temph[0]<<7)) + (temph[0]&temph[1]^~temph[0]&temph[2]) + h64[ji+4] + chunk256[ji+4];
		temph[7] += cacheFunc1;
		//   3                       4         4            4          4            4          4               4      5      4      6      5      6
		temph[3] = cacheFunc1 + ((temph[4]>>2|temph[4]<<30)^(temph[4]>>13|temph[4]<<19)^(temph[4]>>22|temph[4]<<10)) + (temph[4]&temph[5]^temph[4]&temph[6]^temph[5]&temph[6]);
		//                2          7         7            7          7            7          7              7      0       7      1
		cacheFunc1 = temph[2] + ((temph[7]>>6|temph[7]<<26)^(temph[7]>>11|temph[7]<<21)^(temph[7]>>25|temph[7]<<7)) + (temph[7]&temph[0]^~temph[7]&temph[1]) + h64[ji+5] + chunk256[ji+5];
		temph[6] += cacheFunc1;
		//   2                       3         3            3          3            3          3               3      4      3      5      4      5
		temph[2] = cacheFunc1 + ((temph[3]>>2|temph[3]<<30)^(temph[3]>>13|temph[3]<<19)^(temph[3]>>22|temph[3]<<10)) + (temph[3]&temph[4]^temph[3]&temph[5]^temph[4]&temph[5]);
		//                1          6         6            6          6            6          6              6             6       0
		cacheFunc1 = temph[1] + ((temph[6]>>6|temph[6]<<26)^(temph[6]>>11|temph[6]<<21)^(temph[6]>>25|temph[6]<<7)) + (temph[6]&temph[7]^~temph[6]&temph[0]) + h64[ji+6] + chunk256[ji+6];
		temph[5] += cacheFunc1;
		//   1                       2         2            2          2            2          2               2      3      2      4      3      4
		temph[1] = cacheFunc1 + ((temph[2]>>2|temph[2]<<30)^(temph[2]>>13|temph[2]<<19)^(temph[2]>>22|temph[2]<<10)) + (temph[2]&temph[3]^temph[2]&temph[4]^temph[3]&temph[4]);
		//                0          5         5            5          5            5          5              5      6       5      7
		cacheFunc1 = temph[0] + ((temph[5]>>6|temph[5]<<26)^(temph[5]>>11|temph[5]<<21)^(temph[5]>>25|temph[5]<<7)) + (temph[5]&temph[6]^~temph[5]&temph[7]) + h64[ji+7] + chunk256[ji+7];
		temph[4] += cacheFunc1;
		//   0                       1         1            1          1            1          1               1      2      1      3      2      3
		temph[0] = cacheFunc1 + ((temph[1]>>2|temph[1]<<30)^(temph[1]>>13|temph[1]<<19)^(temph[1]>>22|temph[1]<<10)) + (temph[1]&temph[2]^temph[1]&temph[3]^temph[2]&temph[3]);
	}
	h[0] += temph[0];
	h[1] += temph[1];
	h[2] += temph[2];
	h[3] += temph[3];
	h[4] += temph[4];
	h[5] += temph[5];
	h[6] += temph[6];
	h[7] += temph[7];
	memcpy(temph, h, 32);
}

char* HashStr(const char* message, int algorithm, bit64 flaglengthb, bit64 flaglength) {  //���������������������ڼ����ļ���ϣʱ���ñ�����ʱʹ�õ� 
	bit64 length = 0;
	bit64 length8 = 0;              
	bit64 howMany64 = 0;  //�ж��ٸ���64�ֽڿ�
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


	Byte* begin64 = (Byte*)chunk64;  //��chunk64�����ֽڲ���
	bit32* beginMsg = (bit32*)message;


	//��С�˻�������ʹÿ�ĸ��ֽڷ�תһ��---------------------------------------------ССС----------------------------------------------------
	for (bit64 operate = 0; operate < howMany64; operate++) {  //ǰ���������64�ֽڿ飬Ϊ0ʱ��ִ��
		for (bit64 c = 0; c < 16; c++) {  //����64�ֽڿ��ȡ
			*(begin64 + c * 4 + 3) = *(message + 64 * operate + c * 4);  //С��ϵͳ�е�λ��ŵ�λ�ֽڣ���Ϊ��Ҫ�Դ�˷�ʽ��ȡ�ʹ����ֽڿ��е�����
			*(begin64 + c * 4 + 2) = *(message + 64 * operate + c * 4 + 1);  //������С��ϵͳ����Ҫ��֤��λ��ַ�е����ݱ���ȡ����λ
			*(begin64 + c * 4 + 1) = *(message + 64 * operate + c * 4 + 2);  //�����ֽڿ���д���ֽ�ʱ��Ҫ��4�ֽ��еĸ�λ���ݷŵ���λ��ַ�洢
			*(begin64 + c * 4) = *(message + 64 * operate + c * 4 + 3);
		}

		HashSingle64();

	}
	bit64 frontLength = 64 * howMany64;  //��ȡǰ��n��64�ֽڵ��ܳ��ȣ������ṩ����ƫ�ö�ȡԭʼ��Ϣ�еĺ��治��64�ֽڵ�����
	bit64 surplus = length - frontLength;  //������治��64�ֽڲ��ֵĳ���
	bit64 surplus4 = surplus >> 2;  //��Ϊ��С��ϵͳ�У���Ҫÿ�ĸ��ֽ��ĸ��ֽڵĴ������Ի�ȡһ���ж��ٸ���4�ֽ�
	bit64 surplusb = surplus - 4 * surplus4;  //nn�����ֽں��ж��ٸ��ֽ�

	if (surplus > 55 || surplus == 0) {  //ʣ����ֽڷŲ���9���ֽ�ʱ(n==0ʱ������messageΪ64�ֽڵ�����������ʱֻ�����0x80��8�ֽڳ���)

		if (surplus == 0) {  //����Ϊ64�ֽ�������ʱ�����һ��64�ֽڿ鱻���0x8000000 0000...0000 length(8 bits)
			chunk64[0] = 0x80000000;
			for (short i = 1; i < 14; i++) {
				chunk64[i] = 0x00000000;
			}
			bit32* length4 = (bit32*)&length8;  //����8���ֽ�Ϊmessage����
			chunk64[15] = *length4;
			chunk64[14] = *(length4 + 1);

			HashSingle64();

		}
		else {  //��Ϊ55 < surplus < 64�����
			for (bit64 s = 0; s < surplus4; s++) {  //����64�ֽڿ��ȡ
				*(begin64 + s * 4 + 3) = *(message + frontLength + s * 4);
				*(begin64 + s * 4 + 2) = *(message + frontLength + s * 4 + 1);
				*(begin64 + s * 4 + 1) = *(message + frontLength + s * 4 + 2);
				*(begin64 + s * 4) = *(message + frontLength + s * 4 + 3);
			}
			for (bit64 b = 0; b < surplusb; b++) {  //���ʣ��ķ�4�ֽ��������ݣ���0x80��0x00
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

			for (short i = 0; i < 14; i++) {  //���һ���ֽڿ�ǰ��ȫ�����0x00
				chunk64[i] = 0x00000000;
			}
			bit32* length4 = (bit32*)&length8;  //����8���ֽ�Ϊmessage����
			chunk64[15] = *length4;
			chunk64[14] = *(length4 + 1);

			HashSingle64();

		}
	}
	else {  //��Ϊ0 < length < 55�����
		for (bit64 s = 0; s < surplus4; s++) {  //���ǰ��4*surplus4�ֽ�
			*(begin64 + s * 4 + 3) = *(message + frontLength + s * 4);
			*(begin64 + s * 4 + 2) = *(message + frontLength + s * 4 + 1);
			*(begin64 + s * 4 + 1) = *(message + frontLength + s * 4 + 2);
			*(begin64 + s * 4) = *(message + frontLength + s * 4 + 3);
		}
		for (bit64 b = 0; b < surplusb; b++) {  //���ʣ�µĲ���4�ֽڵ����ݺ�0x00
			*(begin64 + surplus4 * 4 + 3 - b) = *(message + length - surplusb + b);
		}
		*(begin64 + surplus4 * 4 + 3 - surplusb) = 0x80;
		for (bit64 bl = 0; bl < 3 - surplusb; bl++) {
			*(begin64 + surplus4 * 4 + 2 - surplusb - bl) = 0x00;
		}
		for (bit64 z = 4*(surplus4 + 1); z < 56; z++) {  //ʣ�µ����0x00
			*(begin64 + z) = 0x00;
		}

		bit32* length4 = (bit32*)&length8;  //����8���ֽ�Ϊmessage����
		chunk64[15] = *length4;
		chunk64[14] = *(length4 + 1);

		HashSingle64();

	}
	h8ToStr();
	return result256;
}


char* HashFile(char* path, int algorithm) {
	FILE* f = fopen(path, "rb");
	_fseeki64(f, 0, SEEK_END);
	bit64 length = _ftelli64(f);
	rewind(f);
	if (length >> 61 != 0) {
		printf("file is too big\n");
		return nullptr;
	}
	const bit64 howBig = 65536;
	bit64 i4 = 0;
	bit64 howMany64 = length >> 6;  //64�ֽڿ����
	bit64 howMany64M = length / howBig;  //64MB�ж��ٸ�
	bit64 surplus64k = howMany64 % (howBig/64);
	bit64 length8 = length << 3;  //��λ��(��Ҫ���ĳ�����Ϣ)
	bit64 surplus = length - 64 * howMany64;  //�����64�ֽ��ֽ���
	if (surplus == 0) { howMany64--; }
	Byte* begin64 = (Byte*)chunk64;
	Byte* begin644 = (Byte*)chunk64;
	char buff[64] = { 0 };

	char* buffM = new char[howBig];
	bit64 cache1 = 0;
	for (bit64 m = 0; m < howMany64M; m++) {
		fread(buffM, 1, howBig, f);
		for (bit64 b = 0; b < howBig/64; b++) {
			cache1 = 64 * b;
			*(begin64 + 0) = buffM[cache1 + 3];
			*(begin64 + 1) = buffM[cache1 + 2];
			*(begin64 + 2) = buffM[cache1 + 1];
			*(begin64 + 3) = buffM[cache1 + 0];
			*(begin64 + 4) = buffM[cache1 + 7];
			*(begin64 + 5) = buffM[cache1 + 6];
			*(begin64 + 6) = buffM[cache1 + 5];
			*(begin64 + 7) = buffM[cache1 + 4];
			*(begin64 + 8) = buffM[cache1 + 11];
			*(begin64 + 9) = buffM[cache1 + 10];
			*(begin64 + 10) = buffM[cache1 + 9];
			*(begin64 + 11) = buffM[cache1 + 8];
			*(begin64 + 12) = buffM[cache1 + 15];
			*(begin64 + 13) = buffM[cache1 + 14];
			*(begin64 + 14) = buffM[cache1 + 13];
			*(begin64 + 15) = buffM[cache1 + 12];
			*(begin64 + 16) = buffM[cache1 + 19];
			*(begin64 + 17) = buffM[cache1 + 18];
			*(begin64 + 18) = buffM[cache1 + 17];
			*(begin64 + 19) = buffM[cache1 + 16];
			*(begin64 + 20) = buffM[cache1 + 23];
			*(begin64 + 21) = buffM[cache1 + 22];
			*(begin64 + 22) = buffM[cache1 + 21];
			*(begin64 + 23) = buffM[cache1 + 20];
			*(begin64 + 24) = buffM[cache1 + 27];
			*(begin64 + 25) = buffM[cache1 + 26];
			*(begin64 + 26) = buffM[cache1 + 25];
			*(begin64 + 27) = buffM[cache1 + 24];
			*(begin64 + 28) = buffM[cache1 + 31];
			*(begin64 + 29) = buffM[cache1 + 30];
			*(begin64 + 30) = buffM[cache1 + 29];
			*(begin64 + 31) = buffM[cache1 + 28];
			*(begin64 + 32) = buffM[cache1 + 35];
			*(begin64 + 33) = buffM[cache1 + 34];
			*(begin64 + 34) = buffM[cache1 + 33];
			*(begin64 + 35) = buffM[cache1 + 32];
			*(begin64 + 36) = buffM[cache1 + 39];
			*(begin64 + 37) = buffM[cache1 + 38];
			*(begin64 + 38) = buffM[cache1 + 37];
			*(begin64 + 39) = buffM[cache1 + 36];
			*(begin64 + 40) = buffM[cache1 + 43];
			*(begin64 + 41) = buffM[cache1 + 42];
			*(begin64 + 42) = buffM[cache1 + 41];
			*(begin64 + 43) = buffM[cache1 + 40];
			*(begin64 + 44) = buffM[cache1 + 47];
			*(begin64 + 45) = buffM[cache1 + 46];
			*(begin64 + 46) = buffM[cache1 + 45];
			*(begin64 + 47) = buffM[cache1 + 44];
			*(begin64 + 48) = buffM[cache1 + 51];
			*(begin64 + 49) = buffM[cache1 + 50];
			*(begin64 + 50) = buffM[cache1 + 49];
			*(begin64 + 51) = buffM[cache1 + 48];
			*(begin64 + 52) = buffM[cache1 + 55];
			*(begin64 + 53) = buffM[cache1 + 54];
			*(begin64 + 54) = buffM[cache1 + 53];
			*(begin64 + 55) = buffM[cache1 + 52];
			*(begin64 + 56) = buffM[cache1 + 59];
			*(begin64 + 57) = buffM[cache1 + 58];
			*(begin64 + 58) = buffM[cache1 + 57];
			*(begin64 + 59) = buffM[cache1 + 56];
			*(begin64 + 60) = buffM[cache1 + 63];
			*(begin64 + 61) = buffM[cache1 + 62];
			*(begin64 + 62) = buffM[cache1 + 61];
			*(begin64 + 63) = buffM[cache1 + 60];
			HashSingle64();
		}
	}
	fread(buffM, 1, surplus64k * 64, f);
	for (bit64 bk = 0; bk < surplus64k; bk++) {
		cache1 = 64 * bk;
		for (bit64 i = 0; i < 16; i++) {
			i4 = i * 4;
			*(begin644 + i4) = buffM[cache1 + i4 + 3];
			*(begin644 + i4 + 1) = buffM[cache1 + i4 + 2];
			*(begin644 + i4 + 2) = buffM[cache1 + i4 + 1];
			*(begin644 + i4 + 3) = buffM[cache1 + i4];
		}
		HashSingle64();
	}
	if (surplus == 0) {
		fread(buff, 1, 64, f);
		fclose(f);
		for (short i = 0; i < 16; i++) {
			*(begin644 + i * 4) = buff[i * 4 + 3];
			*(begin644 + i * 4 + 1) = buff[i * 4 + 2];
			*(begin644 + i * 4 + 2) = buff[i * 4 + 1];
			*(begin644 + i * 4 + 3) = buff[i * 4];
		}

		HashSingle64();

		chunk64[0] = 0x80000000;
		for (short i = 1; i < 14; i++) {
			chunk64[i] = 0x00000000;
		}
		bit32* length4 = (bit32*)&length8;  //����8���ֽ�Ϊmessage����
		chunk64[15] = *length4;
		chunk64[14] = *(length4 + 1);

		HashSingle64();

		h8ToStr();
		delete[] buffM;
		return result256;
	}
	else {
		fread(buff, 1, surplus, f);
		fclose(f);
		buff[surplus] = '\0';
		delete[] buffM;
		return HashStr(buff, 256, surplus, length);
	}
}

