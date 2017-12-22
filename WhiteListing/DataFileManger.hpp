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
	const int SEC_OPTION_POS = 0;
	const int RULE_TYPE_POS = 2;
	const int RULE_PATH_POS = 4;

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
		}
		~DataFileManager()
		{
			ClosePolicyFile();
		}

		std::string GetGlobalSettings() const
		{
			return globalPolicySettings;
		}

		void VerifyPassword();
		void CheckPassword();
		void SetNewPassword();
		RuleFindResult FindRule(AppSecPolicy::SecOption, RuleType,
			const std::string&, std::string&) const;
		void WriteToFile(const RuleData&, WriteType);
		void ListRules() const;

	private:
		void GetPassword(std::string&);
		bool OpenPolicyFile();
		void ClosePolicyFile();
		std::string GetGobalPolicySettings() const;
		void ReorganizePolicyData();

		const unsigned iterations = 1000;	//iterations for PBKDF2
		const unsigned TAG_SIZE = AES::BLOCKSIZE;
		const unsigned KEY_SIZE = AES::MAX_KEYLENGTH;
		ProtectedPtr<SecByteBlock, SecByteBlockSerializer> kdfSalt;
		ProtectedPtr<SecByteBlock, SecByteBlockSerializer> kdfHash;

		const std::string policyFileName = "Policy Settings.dat";
		const std::string policyFileHeader = "Policy Settings\n";
		ProtectedPtr<std::string, StringSerializer> policyData;
		
		std::string globalPolicySettings;
		std::vector<std::string> ruleInfo;		//data of already created rules
		std::vector<std::string> rulePaths;		//paths of created rules for searching
		
		bool rulesAdded = false;
		bool rulesNotSorted = true;
		bool policyDataModified = false;

		std::vector<std::string> executableTypes = {
			"ADE", "ADP", "APPLICATION", "BAS", "BAT", "BGI", "CHM", "CMD", "COM",
			"CPL", "CRT", "DIAGCAB", "DLL", "EXE", "HLP", "HTA", "INF", "INS",
			"ISP", "JS", "JSE", "LNK", "MDB", "MDE", "MSC", "MSI", "MSP", "MST",
			"OCX", "PCD", "PIF", "PS1", "PS2", "PSM", "REG", "SCR", "SCT", "SHS",
			"URL", "VB", "VBE", "VBS", "VBSCRIPT", "WSC", "XAML", "XBAP", "XPI" };
	};
}