#include "SHA2.h"

std::string HashStr(std::string str, int algorithm) {
	std::string shaVal;
	switch (algorithm) {
	case SHA256: {
		char sha256Val[65] = { 0 };
		hashStr(str.c_str(), sha256Val, SHA256);
		shaVal = sha256Val;
		break;
		}
	}
	return shaVal;
}

std::string HashFile(std::string path, int algorithm) {
	std::string shaVal;
	switch (algorithm) {
	case SHA256: {
		char sha256Val[65] = { 0 };
		hashFile((char*)path.c_str(), sha256Val, SHA256);
		shaVal = sha256Val;
		if (shaVal == "Fail") { shaVal = "failed to open file"; }
		if (shaVal == "N") { shaVal = "failed to malloc memory"; }
		break;
	}
	}
	return shaVal;
}