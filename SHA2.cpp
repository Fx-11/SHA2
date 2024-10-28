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

bit32 chunk64[16] = { 0 };  //������Ҫ�����64�ֽڿ飬ÿ�μ���ǰ���ᱻ���£������겻�ı������ݣ�Ĭ����4�ֽڳ��ȷ���
bit32 chunk256[64] = { 0 };  //����64�ֽڿ鱻��䵽256�ֽں�Ľ����һ��ÿ�μ���ǰ���£����������ݲ��䣬Ĭ����4�ֽڳ��ȷ���
bit32 temph8[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,  //����ÿ�μ������м��ϣֵ�����ݲ��䣬����ʱ����
0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};
char result256[65] = { '0' };  //��64�ֽ��ַ�����ʽ����sha256������ɺ�Ľ��(ʮ������)


bool isBigEndian() {  // �жϵ�ǰ���л����Ƿ�Ϊ���
	bit32 num = 0x00000011;
	Byte* p = (Byte*)&num;
	if (*p == 0x11) {
		return false;
	}
	else {
		return true;
	}
};

bit32 crs(bit32 original, int bits) {  // ��4�ֽ�originalѭ������bitsλ�����ظ�ֵ
	bits = bits % 32;
	bit32 temp = original;
	original = original >> bits;
	temp = temp << (32 - bits);
	return (original | temp);
}

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


void HashSingle64(bool isDebug) {
	if (isDebug) { printHexFromArry(chunk64, 16); }
	for (short i = 0; i < 16; i++) {  // ��64�ֽڵ���Ϣ���䵽256�ֽ�
		chunk256[i] = chunk64[i];  //ǰ64�ֽ�ֱ�Ӹ���
	}
	for (short j = 16; j < 64; j++) {  //ѭ�����4�ֽ�
		bit32 s0 = chunk256[j - 15];
		bit32 s1 = chunk256[j - 2];
		bit32 s2 = chunk256[j - 16];
		bit32 s3 = chunk256[j - 7];
		s0 = crs(s0, 7) ^ crs(s0, 18) ^ (s0 >> 3);
		s1 = crs(s1, 17) ^ crs(s1, 19) ^ (s1 >> 10);
		chunk256[j] = s0 + s1 + s2 + s3;
	}

	for (int i = 0; i < 64; i++) {  //64��ѭ�������������ȫ��temph8����
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
	for (short i = 0; i < 8; i++) {  //����h8��ϣֵ����
		h8[i] += temph8[i];
		temph8[i] = h8[i];
	}
}



void h8ToStr() { //�������Ľ������h8�д洢�Ĺ�ϣֵת��Ϊ�ַ�����ʽ�����洢��result256�У�,��ˢ��h8��temph8Ϊ��ʼ����ֵ
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

char* HashStr(const char* message, int algorithm, bool isDebug, bit64 flaglengthb, bit64 flaglength) {  //���������������������ڼ����ļ���ϣʱ���ñ�����ʱʹ�õ� 
	bit64 length = 0;               //isDebugΪtrueʱ����ִ�й����д�ӡ��ÿ���ֽڿ�
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

	if (isDebug) { std::cout << length << std::endl; }

	Byte* begin64 = (Byte*)chunk64;  //��chunk64�����ֽڲ���
	bit32* beginMsg = (bit32*)message;

	if (isBigEnd) {  //�ڴ�˻����а����򼴿�---------------------------------------------------����-----------------------------------------------
		for (bit64 operate = 0; operate < howMany64; operate++) {  //ǰ�����64�ֽڿ�
			for (bit64 c = 0; c < 64; c++) {  //����64�ֽڿ��ȡ
				*(begin64 + c) = *(message + 64*operate+c);
			}
			HashSingle64(isDebug);

		}
		bit64 frontLength = 64 * howMany64;
		bit64 surplus = length - frontLength;
		if (surplus > 55 || surplus == 0) {  //ʣ����ֽڷŲ���9���ֽ�ʱ
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
				for (bit64 s = 0; s < surplus; s++) {  //����64�ֽڿ��ȡ
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
			for (bit64 s = 0; s < surplus; s++) {  //����64�ֽڿ��ȡ
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
	}  //------------------------------------------------------------------------�˶˶�-----------------------------------------------------------
	else {  //��С�˻�������ʹÿ�ĸ��ֽڷ�תһ��---------------------------------------------ССС----------------------------------------------------
		for (bit64 operate = 0; operate < howMany64; operate++) {  //ǰ���������64�ֽڿ飬Ϊ0ʱ��ִ��
			for (bit64 c = 0; c < 16; c++) {  //����64�ֽڿ��ȡ
				*(begin64 + c * 4 + 3) = *(message + 64 * operate + c * 4);  //С��ϵͳ�е�λ��ŵ�λ�ֽڣ���Ϊ��Ҫ�Դ�˷�ʽ��ȡ�ʹ����ֽڿ��е�����
				*(begin64 + c * 4 + 2) = *(message + 64 * operate + c * 4 + 1);  //������С��ϵͳ����Ҫ��֤��λ��ַ�е����ݱ���ȡ����λ
				*(begin64 + c * 4 + 1) = *(message + 64 * operate + c * 4 + 2);  //�����ֽڿ���д���ֽ�ʱ��Ҫ��4�ֽ��еĸ�λ���ݷŵ���λ��ַ�洢
				*(begin64 + c * 4) = *(message + 64 * operate + c * 4 + 3);
			}

			HashSingle64(isDebug);

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

				HashSingle64(isDebug);

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

				if (isDebug) { printHexFromArry(chunk64, 16); }
				HashSingle64(isDebug);

				for (short i = 0; i < 14; i++) {  //���һ���ֽڿ�ǰ��ȫ�����0x00
					chunk64[i] = 0x00000000;
				}
				bit32* length4 = (bit32*)&length8;  //����8���ֽ�Ϊmessage����
				chunk64[15] = *length4;
				chunk64[14] = *(length4 + 1);

				HashSingle64(isDebug);

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

			HashSingle64(isDebug);

		}
		h8ToStr();
		return result256;
	}
}

char* HashFile(const char* path, int algorithm, bool isDebug) {
	std::fstream f(path, std::ios::in | std::ios::binary | std::ios::ate);
	std::streampos endP = f.tellg();  //��ȡ�ļ�����
	f.seekg(std::ios::beg);
	//if (endP >> 61 != 0) {
	//	std::cerr << "file is too big";
	//	return nullptr;
	//}
	bit64 length = endP;  //�ļ��ܳ���(�ֽ�)
	bit64 howMany64 = length >> 6;  //64�ֽڿ����
	bit64 length8 = length << 3;  //��λ��(��Ҫ���ĳ�����Ϣ)
	bit64 surplus = length - 64 * howMany64;  //�����64�ֽ��ֽ���
	if (surplus == 0) { howMany64--; }
	Byte* begin64 = (Byte*)chunk64;

	if (!isBigEnd) {  //С�˻����������
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
			bit32* length4 = (bit32*)&length8;  //����8���ֽ�Ϊmessage����
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

