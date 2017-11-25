#include "Crypto++\aes.h"
#include "Protected.hpp"
#include "Windows.h"
#include <filesystem>
#include <fstream>
#include <string>
#pragma once

class DataFileManager
{
public:
	explicit DataFileManager() 
	{
		kdfSalt.resize(KEY_SIZE);
		kdfHash.resize(KEY_SIZE * 2);
		policyData.assign(new std::string);

		SetNewPassword();
		OpenPolicyFile();
	}
	~DataFileManager() 
	{
		ClosePolicyFile();
	}

	void OpenPolicyFile();
	void ClosePolicyFile();
	void CheckPassword();

private:
	bool FindDataFile();
	void SetNewPassword();
	void GetPassword(std::string&);

	const size_t iterations = 1000000;	//iterations for PBKDF2
	const size_t TAG_SIZE = CryptoPP::AES::BLOCKSIZE;
	const size_t KEY_SIZE = CryptoPP::AES::MAX_KEYLENGTH;
	CryptoPP::SecByteBlock kdfSalt;
	CryptoPP::SecByteBlock kdfHash;

	std::string policyFileName = "abc.txt";
	Protected<std::string> policyData;
};