#include "AppSecPolicy.hpp"
#include "ProtectedPtr.hpp"
#include "include\Crypto++\aes.h"
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
		DataFileManager()
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
		std::vector<RuleData> FindRulesInDir(const std::string&) const;
		std::vector<RuleData> GetDeletedFiles(const std::vector<RuleData>&);
		void UpdateUserRules(const std::vector<UserRule>&, bool);
		void InsertNewEntries(const std::vector<RuleDataPtr>&);
		void UpdateEntries(SecOption, const std::vector<RuleDataPtr>&);
		void RemoveDeletedFiles(const std::vector<RuleData>&);
		void RemoveOldEntries();
		void ListRules() const;
		void WriteChanges();

	private:
		void GetPassword(std::string&);
		bool OpenPolicyFile();
		void ClosePolicyFile();
		
		RuleFindResult FindUserRule(SecOption, RuleType, 
			const std::string&, std::size_t&, bool&) const;
		RuleData StringToRuleData(const std::string&) const;
		std::string RuleDataToString(const RuleData&) const;
		void SortRules();

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

		std::vector<std::string> userRuleInfo;	//dirs the user entered to do work on
		std::vector<std::string> userRulePaths;	//extracted paths from userRuleInfo

		std::vector<std::string> updatedRules;	//rules that have been updated or switched
		std::vector<std::string> removedRules;	//rules that have been/to be removed

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