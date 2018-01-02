#include "AppSecPolicy.hpp"
#include "ProtectedPtr.hpp"
#include "Crypto++\aes.h"

#include <filesystem>
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
			CloseHandle(policyFileHandle);
		}

		std::string GetGlobalSettings() const
		{
			if (passwordReset)
				return GetCurrentPolicySettings();

			else
				return globalPolicySettings;
		}
		std::string GetCurrentPolicySettings() const;

		void VerifyPassword(std::string&);
		void CheckPassword(std::string&);
		void SetNewPassword();
		RuleFindResult FindRule(SecOption, RuleType,
			const std::string&, RuleData&) const;
		bool FindRulesInDir(const std::string&, std::vector<RuleData>&) const;
		void UpdateUserRules(const std::vector<UserRule>&, bool);
		void InsertNewEntries(const std::vector<std::shared_ptr<RuleData>>&);
		void SwitchEntries(SecOption);
		void UpdateEntries(SecOption, const std::vector<std::shared_ptr<RuleData>>&);
		void RemoveOldEntries();
		void ListRules() const;

	private:
		void GetPassword(std::string&);
		bool OpenPolicyFile();
		void ClosePolicyFile();
		
		RuleFindResult FindUserRule(SecOption, RuleType, 
			const std::string&, std::size_t&, bool&) const;
		RuleData StringToRuleData(const std::string&) const;
		std::string RuleDataToString(const RuleData&) const;
		void ReorganizePolicyData();

		const unsigned iterations = 1000;	//iterations for PBKDF2
		const unsigned TAG_SIZE = AES::BLOCKSIZE;
		const unsigned KEY_SIZE = AES::MAX_KEYLENGTH;
		ProtectedPtr<SecByteBlock, SecByteBlockSerializer> kdfSalt;
		ProtectedPtr<SecByteBlock, SecByteBlockSerializer> kdfHash;

		HANDLE policyFileHandle;
		const std::string policyFileName = "Policy Settings.dat";
		const std::string policyFileHeader = "Policy Settings\n";
		ProtectedPtr<std::string, StringSerializer> policyData;
		
		std::string globalPolicySettings;

		std::vector<std::string> userRuleInfo;
		std::vector<std::string> userRulePaths;

		std::vector<std::string> switchedRules;
		std::vector<std::string> removedRules;

		std::vector<std::string> ruleInfo;		//data of already created rules
		std::vector<std::string> rulePaths;		//paths of created rules for searching
		
		bool rulesAdded = false;
		bool passwordReset = false;
		bool policyDataModified = false;

		bool rulesNotSorted = true;
		bool userRulesNotSorted = true;

		std::vector<std::string> executableTypes = {
			"ADE", "ADP", "APPLICATION", "BAS", "BAT", "BGI", "CHM", "CMD", "COM",
			"CPL", "CRT", "DIAGCAB", "DLL", "EXE", "HLP", "HTA", "INF", "INS",
			"ISP", "JS", "JSE", "LNK", "MDB", "MDE", "MSC", "MSI", "MSP", "MST",
			"OCX", "PCD", "PIF", "PS1", "PS2", "PSM", "REG", "SCR", "SCT", "SHS",
			"URL", "VB", "VBE", "VBS", "VBSCRIPT", "WSC", "XAML", "XBAP", "XPI" };
	};
}