#include "AppSecPolicy.hpp"
#include "ProtectedPtr.hpp"
#include "Crypto++\aes.h"

#include <filesystem>
#include <fstream>
#include <string>
#include <vector>
#include <tuple>
#pragma once

using CryptoPP::AES;
using CryptoPP::SecByteBlock;
using namespace Protected_Ptr;
using namespace AppSecPolicy;
namespace fs = std::experimental::filesystem;

namespace AppSecPolicy
{
	class DataFileManager
	{
	public:
		explicit DataFileManager()
		{
			kdfSalt.SetWipeOnExit(false);
			kdfHash.SetWipeOnExit(false);
			kdfSalt.assign(new SecByteBlock(KEY_SIZE));
			kdfHash.assign(new SecByteBlock(KEY_SIZE * 2));
			policyData.assign(new std::string);

			if (fs::exists(policyFileName))
				CheckPassword();
			else
				SetNewPassword();
		}
		~DataFileManager()
		{
			WriteChanges();
		}

		void CheckPassword();
		void SetNewPassword();
		void WriteToFile(const RuleData&);

	private:
		void GetPassword(std::string&);
		inline bool OpenPolicyFile(bool);
		inline void ClosePolicyFile();
		void WriteChanges();

		const size_t iterations = 10000;	//iterations for PBKDF2
		const size_t TAG_SIZE = AES::BLOCKSIZE;
		const size_t KEY_SIZE = AES::MAX_KEYLENGTH;
		ProtectedPtr<SecByteBlock, SecByteBlockSerializer> kdfSalt;
		ProtectedPtr<SecByteBlock, SecByteBlockSerializer> kdfHash;

		const std::string policyFileName = "Policy Settings.dat";
		const std::string policyFileHeader = "\nPolicy Settings\n";
		ProtectedPtr<std::string, StringSerializer> policyData;
	};
}