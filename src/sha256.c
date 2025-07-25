#include "sha256.h"

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
const bit32 h[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };



void* initialStat(bit8* data, bit64 length, int algorithm) {  // ������ϣ״̬������Ҫ���������ָ��ͳ����Լ�ѡ���ϣ�㷨����ʼ����ϣ״̬������״̬�ṹ��ָ��(ע��˴����ᴦ��ĩβ����n�ֽڵ�����)
	void* statP = NULL;
	switch (algorithm) {
	case SHA256:
		struct sha256Stat* sha256StatP = (struct sha256Stat*)calloc(1, sizeof(struct sha256Stat)); //����sha256�㷨��״̬��Ϣ�ڴ�
		if (sha256StatP == NULL) { return NULL; }
		sha256StatP->data = data;
		sha256StatP->remainingCount = length / 64; //�ж��ٸ�64�ֽڿ飬�����ں����жϺ�ʱ����
		memcpy(sha256StatP->h, h, 32);  // ���Ƹ�ֵ8����ϣ����
		memcpy(sha256StatP->temph, h, 32);
		statP = sha256StatP;
		break;
	}
	return statP;
}
void freeStat(void* statP) {
	free(statP);
}

void updataStat(void* statP, bit8* data, bit64 length, int algorithm) {  // ���ֹ�ϣֵ���䣬����Ҫ��������ݡ�(ע��ͬ�����ᴦ��ĩβ����6n�ֽڵ�����)
	switch (algorithm) {
	case SHA256: {
		struct sha256Stat* sha256StatP = (struct sha256Stat*)statP;
		sha256StatP->data = data;
		sha256StatP->remainingCount = length / 64; //�ж��ٸ�64�ֽڿ飬�����ں����жϺ�ʱ����
		break;
	}
	}
}

void preProcessStat(void* statP, bit64 totalLength, int algorithm) {  // ע��ú�����������ĩβ����n�ֽڵ�����,һ��Ҫ�ڹ�ϣ״̬δ��ʼ����ʱ���á�������״̬��data�ĳ��ȣ�����ĩβ2��64�ֽڵ����ݣ�
	switch (algorithm) {
	case SHA256:
		struct sha256Stat* sha256StatP = (struct sha256Stat*)statP;
		bit32 remaining64 = totalLength % 64;  // �����ȡ����64���������Դ�Ϊ�����������
		bit64 lengthB = LB8(totalLength*8);  // ����һ�����ȵĴ�˱�����С��ϵͳ��Ҫת��
		bit8* end128 = (bit8*)(sha256StatP->end128);  // ���end128�ֽ�����ָ�룬���㸳ֵ
		if (remaining64 <= 55) {  // 1+8�ֽڷŵ��£����һ��64�ֽھ���
			memcpy(end128, sha256StatP->data + 64 * sha256StatP->remainingCount, remaining64); // ���²���64�ֽڵ����ݸ��ƹ���
			end128[remaining64] = 0x80;
			((bit64*)(sha256StatP->end128))[7] = lengthB;  // ĩβ����˳���
			sha256StatP->isCalc128 = 1;
		}
		else {
			memcpy(end128, sha256StatP->data + 64 * sha256StatP->remainingCount, remaining64); // ���²���64�ֽڵ����ݸ��ƹ���
			end128[remaining64] = 0x80;
			((bit64*)(sha256StatP->end128))[15] = lengthB;
			sha256StatP->isCalc128 = 2;
		}
		return;
		break;
	}
}

//===========================================��Ҫ����ƿ��=====================================================================================================================
void hash256(struct sha256Stat* sha256StatP) {  // ��ȡ״̬��dataָ��ָ��ĺ���64�ֽڣ����㲢����״̬��ϣ
	bit32 chunk256[64] = { 0 };
	bit8* Dst = (bit8*)chunk256; bit8* Src = sha256StatP->data;
	for (bit64 i = 0; i < 64; i += 16) {
		*(Dst + i) = *(Src + i + 3);
		*(Dst + i + 1) = *(Src + i + 2);
		*(Dst + i + 2) = *(Src + i + 1);
		*(Dst + i + 3) = *(Src + i);
		*(Dst + i + 4) = *(Src + i + 7);
		*(Dst + i + 5) = *(Src + i + 6);
		*(Dst + i + 6) = *(Src + i + 5);
		*(Dst + i + 7) = *(Src + i + 4);
		*(Dst + i + 8) = *(Src + i + 11);
		*(Dst + i + 9) = *(Src + i + 10);
		*(Dst + i + 10) = *(Src + i + 9);
		*(Dst + i + 11) = *(Src + i + 8);
		*(Dst + i + 12) = *(Src + i + 15);
		*(Dst + i + 13) = *(Src + i + 14);
		*(Dst + i + 14) = *(Src + i + 13);
		*(Dst + i + 15) = *(Src + i + 12);
	}
	sha256StatP->data += 64;
	bit32 s0 = 0;
	bit32 s1 = 0;
	bit32 cacheFunc1 = 0;
	short ji = 0;
	for (short j = 16; j < 64; j++) {  //ѭ�����4�ֽ�
		s0 = chunk256[j - 15];
		s1 = chunk256[j - 2];
		s0 = ((s0 >> 7) | (s0 << 25)) ^ ((s0 >> 18) | (s0 << 14)) ^ (s0 >> 3);
		s1 = ((s1 >> 17) | (s1 << 15)) ^ ((s1 >> 19) | (s1 << 13)) ^ (s1 >> 10);
		chunk256[j] = s0 + s1 + chunk256[j - 16] + chunk256[j - 7];
	}
	//����Ϊ16�����ֽ����䵽64�����ֽڵĹ���  #�˴��������ʹ��������-�����߶��߳�ģ�ͻ���ˮ�߻����м��ټ���
	//����Ϊ�������h[0]-h[7]ֵ�Ĺ���
	for (short i = 0; i < 8; i++) {
		ji = i * 8;
		//                7          4         4            4          4            4          4              4      5       4      6
		cacheFunc1 = sha256StatP->temph[7] + ((sha256StatP->temph[4] >> 6 | sha256StatP->temph[4] << 26) ^ (sha256StatP->temph[4] >> 11 | sha256StatP->temph[4] << 21) ^ (sha256StatP->temph[4] >> 25 | sha256StatP->temph[4] << 7)) + (sha256StatP->temph[4] & sha256StatP->temph[5] ^ ~sha256StatP->temph[4] & sha256StatP->temph[6]) + h64[ji] + chunk256[ji];
		sha256StatP->temph[3] += cacheFunc1;
		//   7                       0         0            0          0            0          0               0      1      0      2      1      2
		sha256StatP->temph[7] = cacheFunc1 + ((sha256StatP->temph[0] >> 2 | sha256StatP->temph[0] << 30) ^ (sha256StatP->temph[0] >> 13 | sha256StatP->temph[0] << 19) ^ (sha256StatP->temph[0] >> 22 | sha256StatP->temph[0] << 10)) + (sha256StatP->temph[0] & sha256StatP->temph[1] ^ sha256StatP->temph[0] & sha256StatP->temph[2] ^ sha256StatP->temph[1] & sha256StatP->temph[2]);
		//                6          3         3            3          3            3          3              3      4       3      5
		cacheFunc1 = sha256StatP->temph[6] + ((sha256StatP->temph[3] >> 6 | sha256StatP->temph[3] << 26) ^ (sha256StatP->temph[3] >> 11 | sha256StatP->temph[3] << 21) ^ (sha256StatP->temph[3] >> 25 | sha256StatP->temph[3] << 7)) + (sha256StatP->temph[3] & sha256StatP->temph[4] ^ ~sha256StatP->temph[3] & sha256StatP->temph[5]) + h64[ji + 1] + chunk256[ji + 1];
		sha256StatP->temph[2] += cacheFunc1;
		//   6                       7         7            7          7            7          7               7      0      7      1      0      1
		sha256StatP->temph[6] = cacheFunc1 + ((sha256StatP->temph[7] >> 2 | sha256StatP->temph[7] << 30) ^ (sha256StatP->temph[7] >> 13 | sha256StatP->temph[7] << 19) ^ (sha256StatP->temph[7] >> 22 | sha256StatP->temph[7] << 10)) + (sha256StatP->temph[7] & sha256StatP->temph[0] ^ sha256StatP->temph[7] & sha256StatP->temph[1] ^ sha256StatP->temph[0] & sha256StatP->temph[1]);
		//                5          2         2            2          2            2          2              2      3       2      4
		cacheFunc1 = sha256StatP->temph[5] + ((sha256StatP->temph[2] >> 6 | sha256StatP->temph[2] << 26) ^ (sha256StatP->temph[2] >> 11 | sha256StatP->temph[2] << 21) ^ (sha256StatP->temph[2] >> 25 | sha256StatP->temph[2] << 7)) + (sha256StatP->temph[2] & sha256StatP->temph[3] ^ ~sha256StatP->temph[2] & sha256StatP->temph[4]) + h64[ji + 2] + chunk256[ji + 2];
		sha256StatP->temph[1] += cacheFunc1;
		//   5                       6         6            6          6            6          6               6      7      6      0      7      0
		sha256StatP->temph[5] = cacheFunc1 + ((sha256StatP->temph[6] >> 2 | sha256StatP->temph[6] << 30) ^ (sha256StatP->temph[6] >> 13 | sha256StatP->temph[6] << 19) ^ (sha256StatP->temph[6] >> 22 | sha256StatP->temph[6] << 10)) + (sha256StatP->temph[6] & sha256StatP->temph[7] ^ sha256StatP->temph[6] & sha256StatP->temph[0] ^ sha256StatP->temph[7] & sha256StatP->temph[0]);
		//                4          1         1            1          1            1          1              1      2       1      3
		cacheFunc1 = sha256StatP->temph[4] + ((sha256StatP->temph[1] >> 6 | sha256StatP->temph[1] << 26) ^ (sha256StatP->temph[1] >> 11 | sha256StatP->temph[1] << 21) ^ (sha256StatP->temph[1] >> 25 | sha256StatP->temph[1] << 7)) + (sha256StatP->temph[1] & sha256StatP->temph[2] ^ ~sha256StatP->temph[1] & sha256StatP->temph[3]) + h64[ji + 3] + chunk256[ji + 3];
		sha256StatP->temph[0] += cacheFunc1;
		//   4                       5         5            5          5            5          5               5      6      5      7      6      7
		sha256StatP->temph[4] = cacheFunc1 + ((sha256StatP->temph[5] >> 2 | sha256StatP->temph[5] << 30) ^ (sha256StatP->temph[5] >> 13 | sha256StatP->temph[5] << 19) ^ (sha256StatP->temph[5] >> 22 | sha256StatP->temph[5] << 10)) + (sha256StatP->temph[5] & sha256StatP->temph[6] ^ sha256StatP->temph[5] & sha256StatP->temph[7] ^ sha256StatP->temph[6] & sha256StatP->temph[7]);
		//                3          0         0            0          0            0          0              0      1       0      2
		cacheFunc1 = sha256StatP->temph[3] + ((sha256StatP->temph[0] >> 6 | sha256StatP->temph[0] << 26) ^ (sha256StatP->temph[0] >> 11 | sha256StatP->temph[0] << 21) ^ (sha256StatP->temph[0] >> 25 | sha256StatP->temph[0] << 7)) + (sha256StatP->temph[0] & sha256StatP->temph[1] ^ ~sha256StatP->temph[0] & sha256StatP->temph[2]) + h64[ji + 4] + chunk256[ji + 4];
		sha256StatP->temph[7] += cacheFunc1;
		//   3                       4         4            4          4            4          4               4      5      4      6      5      6
		sha256StatP->temph[3] = cacheFunc1 + ((sha256StatP->temph[4] >> 2 | sha256StatP->temph[4] << 30) ^ (sha256StatP->temph[4] >> 13 | sha256StatP->temph[4] << 19) ^ (sha256StatP->temph[4] >> 22 | sha256StatP->temph[4] << 10)) + (sha256StatP->temph[4] & sha256StatP->temph[5] ^ sha256StatP->temph[4] & sha256StatP->temph[6] ^ sha256StatP->temph[5] & sha256StatP->temph[6]);
		//                2          7         7            7          7            7          7              7      0       7      1
		cacheFunc1 = sha256StatP->temph[2] + ((sha256StatP->temph[7] >> 6 | sha256StatP->temph[7] << 26) ^ (sha256StatP->temph[7] >> 11 | sha256StatP->temph[7] << 21) ^ (sha256StatP->temph[7] >> 25 | sha256StatP->temph[7] << 7)) + (sha256StatP->temph[7] & sha256StatP->temph[0] ^ ~sha256StatP->temph[7] & sha256StatP->temph[1]) + h64[ji + 5] + chunk256[ji + 5];
		sha256StatP->temph[6] += cacheFunc1;
		//   2                       3         3            3          3            3          3               3      4      3      5      4      5
		sha256StatP->temph[2] = cacheFunc1 + ((sha256StatP->temph[3] >> 2 | sha256StatP->temph[3] << 30) ^ (sha256StatP->temph[3] >> 13 | sha256StatP->temph[3] << 19) ^ (sha256StatP->temph[3] >> 22 | sha256StatP->temph[3] << 10)) + (sha256StatP->temph[3] & sha256StatP->temph[4] ^ sha256StatP->temph[3] & sha256StatP->temph[5] ^ sha256StatP->temph[4] & sha256StatP->temph[5]);
		//                1          6         6            6          6            6          6              6             6       0
		cacheFunc1 = sha256StatP->temph[1] + ((sha256StatP->temph[6] >> 6 | sha256StatP->temph[6] << 26) ^ (sha256StatP->temph[6] >> 11 | sha256StatP->temph[6] << 21) ^ (sha256StatP->temph[6] >> 25 | sha256StatP->temph[6] << 7)) + (sha256StatP->temph[6] & sha256StatP->temph[7] ^ ~sha256StatP->temph[6] & sha256StatP->temph[0]) + h64[ji + 6] + chunk256[ji + 6];
		sha256StatP->temph[5] += cacheFunc1;
		//   1                       2         2            2          2            2          2               2      3      2      4      3      4
		sha256StatP->temph[1] = cacheFunc1 + ((sha256StatP->temph[2] >> 2 | sha256StatP->temph[2] << 30) ^ (sha256StatP->temph[2] >> 13 | sha256StatP->temph[2] << 19) ^ (sha256StatP->temph[2] >> 22 | sha256StatP->temph[2] << 10)) + (sha256StatP->temph[2] & sha256StatP->temph[3] ^ sha256StatP->temph[2] & sha256StatP->temph[4] ^ sha256StatP->temph[3] & sha256StatP->temph[4]);
		//                0          5         5            5          5            5          5              5      6       5      7
		cacheFunc1 = sha256StatP->temph[0] + ((sha256StatP->temph[5] >> 6 | sha256StatP->temph[5] << 26) ^ (sha256StatP->temph[5] >> 11 | sha256StatP->temph[5] << 21) ^ (sha256StatP->temph[5] >> 25 | sha256StatP->temph[5] << 7)) + (sha256StatP->temph[5] & sha256StatP->temph[6] ^ ~sha256StatP->temph[5] & sha256StatP->temph[7]) + h64[ji + 7] + chunk256[ji + 7];
		sha256StatP->temph[4] += cacheFunc1;
		//   0                       1         1            1          1            1          1               1      2      1      3      2      3
		sha256StatP->temph[0] = cacheFunc1 + ((sha256StatP->temph[1] >> 2 | sha256StatP->temph[1] << 30) ^ (sha256StatP->temph[1] >> 13 | sha256StatP->temph[1] << 19) ^ (sha256StatP->temph[1] >> 22 | sha256StatP->temph[1] << 10)) + (sha256StatP->temph[1] & sha256StatP->temph[2] ^ sha256StatP->temph[1] & sha256StatP->temph[3] ^ sha256StatP->temph[2] & sha256StatP->temph[3]);
	}

	sha256StatP->h[0] += sha256StatP->temph[0];
	sha256StatP->h[1] += sha256StatP->temph[1];
	sha256StatP->h[2] += sha256StatP->temph[2];
	sha256StatP->h[3] += sha256StatP->temph[3];
	sha256StatP->h[4] += sha256StatP->temph[4];
	sha256StatP->h[5] += sha256StatP->temph[5];
	sha256StatP->h[6] += sha256StatP->temph[6];
	sha256StatP->h[7] += sha256StatP->temph[7];
	sha256StatP->temph[0] = sha256StatP->h[0];
	sha256StatP->temph[1] = sha256StatP->h[1];
	sha256StatP->temph[2] = sha256StatP->h[2];
	sha256StatP->temph[3] = sha256StatP->h[3];
	sha256StatP->temph[4] = sha256StatP->h[4];
	sha256StatP->temph[5] = sha256StatP->h[5];
	sha256StatP->temph[6] = sha256StatP->h[6];
	sha256StatP->temph[7] = sha256StatP->h[7];
	sha256StatP->remainingCount--;
}
//========================================================================================================================================================


void hashEnd256(struct sha256Stat* sha256StatP) {  // ������������ĩβ�������ݵĹ�ϣֵ��һ����preProcessStat�������ʹ��
	if (sha256StatP->isCalc128 == 1) {
		sha256StatP->data = (bit8*)sha256StatP->end128;
		sha256StatP->remainingCount = 1;
		hash256(sha256StatP);

		for (short j = 0; j < 8; j++) {
			sha256StatP->h[j] = LB4(sha256StatP->h[j]);
		}
		toHex((bit8*)(sha256StatP->h), 32, sha256StatP->sha256, false);
		sha256StatP->sha256[64] = '\0';
	}
	if (sha256StatP->isCalc128 == 2) {
		sha256StatP->data = (bit8*)sha256StatP->end128;
		sha256StatP->remainingCount = 2;
		hash256(sha256StatP);
		hash256(sha256StatP);

		for (short j = 0; j < 8; j++) {
			sha256StatP->h[j] = LB4(sha256StatP->h[j]);
		}
		toHex((bit8*)(sha256StatP->h), 32, sha256StatP->sha256, false);
		sha256StatP->sha256[64] = '\0';
	}
}
void autoHash256(struct sha256Stat* sha256StatP) {  //�Զ��������ϣ״̬��ǰn���ֽڿ�Ĺ�ϣֵ
	while (sha256StatP->remainingCount != 0) {
		hash256(sha256StatP);
	}
}



void hashStr(const char* str, char* buff, int algorithm) {
	struct sha256Stat* sha256StatP = NULL;
	sha256StatP = (struct sha256Stat*)initialStat((bit8*)str, strlen(str), SHA256);
	if (sha256StatP == NULL) { buff[0] = 'N'; buff[1] = '\0'; return; }
	preProcessStat(sha256StatP, strlen(str), SHA256);
	autoHash256(sha256StatP);
	hashEnd256(sha256StatP);
	memcpy(buff, sha256StatP->sha256, 65);
	freeStat(sha256StatP);
	return;
}

void hashFile(const char* path, char* buff, int algorithm) {
	bit64 buffSize = 65536;  // �ļ���ȡ��������С��64KB
	bit8* fbuff = (bit8*)malloc(buffSize);
	struct sha256Stat* sha256StatP = NULL;
	sha256StatP = (struct sha256Stat*)initialStat(fbuff, buffSize, SHA256);
	if (sha256StatP == NULL || fbuff == NULL) { buff[0] = 'N'; buff[1] = '\0'; return; }

	FILE* f = fopen(path, "rb");
	if (f == NULL) { buff[0] = 'F'; buff[1] = 'a'; buff[2] = 'i'; buff[3] = 'l'; buff[4] = '\0'; return; }
	_fseeki64(f, 0, SEEK_END);
	bit64 fileSize = _ftelli64(f);  //��ȡ�ļ���С
	rewind(f);
	if (fileSize >> 61 != 0) {
		printf("file is too big\n");
		return;
	}

	bit64 countBuffSize = fileSize / buffSize;  //�ļ���С���������ٸ�������
	bit64 countRemaining = fileSize % buffSize;  //�ļ����㻺������С�ĳ���

	for (bit64 b = 0; b < countBuffSize; b++) {
		fread(fbuff, 1, buffSize, f);
		updataStat(sha256StatP, fbuff, buffSize, 256);
		autoHash256(sha256StatP);
	}

	fread(fbuff, 1, countRemaining, f);
	updataStat(sha256StatP, fbuff, countRemaining, 256);
	preProcessStat(sha256StatP, fileSize, SHA256);
	autoHash256(sha256StatP);
	hashEnd256(sha256StatP);
	memcpy(buff, sha256StatP->sha256, 65);
	freeStat(sha256StatP);
	free(fbuff);
	return;
}
