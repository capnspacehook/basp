#include "AppSecPolicy.hpp"
#include "ProtectedPtr.hpp"
#include "include\Crypto++\aes.h"

#include <optional>
#include <string_view>
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

	using VecStrIt = std::vector<std::string>::iterator;
	using VecStrConstIt = std::vector<std::string>::const_iterator;
	using VecStrViewConstIt = std::vector<std::string_view>::const_iterator;

	class DataFileManager
	{
	public:
		explicit DataFileManager(std::string &prgmName) : policyFileName(prgmName + ":Zone.Idenitfier")
		{
			kdfSalt.assign(SecByteBlock(KEY_SIZE));
			kdfHash.assign(SecByteBlock(KEY_SIZE * 2));
			policyData.assign(std::string());
		}
		~DataFileManager()
		{	
			ClosePolicyFile();
			CloseHandle(policyFileHandle);
		}

		bool IsFirstTimeRun() const noexcept
		{
			return firstTimeRun;
		}
		bool AreRulesCreated()
		{
			const auto foundPos = policyData->find('\n', KEY_SIZE + policyFileHeader.size());
			const bool rulesCreated = foundPos == policyData->size() - 1;
			policyData.ProtectMemory(true);
			return rulesCreated;
		}
		std::string GetGlobalSettings()
		{
			if (passwordReset)
			{
				passwordReset = false;
				globalPolicySettings = GetCurrentPolicySettings();
				return globalPolicySettings;
			}

			else
				return globalPolicySettings;
		}
		std::string GetCurrentPolicySettings() const;
		std::string GetRuleList()
		{
			std::string ruleList = *policyData;
			policyData.ProtectMemory(true);
			return ruleList;
		}

		static RuleData StringToRuleData(const std::string&);
		static std::string RuleDataToString(const RuleData&);

		void VerifyPassword(std::string&&);
		void CheckPassword(std::string&);
		void SetNewPassword(std::string&);
		RuleFindResult FindRule(SecOption, RuleType,
			const std::string&, RuleData&) const;
		std::vector<RuleData> FindRulesInDir(const std::string&) const;
		std::vector<RuleData> GetDeletedFiles(const std::vector<RuleData>&);
		void UpdateUserRules(const std::vector<UserRule>&, bool);
		void InsertNewEntries(const std::vector<RuleDataPtr>&);
		void UpdateEntries(SecOption, const std::vector<RuleDataPtr>&);
		void RemoveDeletedFiles(const std::vector<RuleData>&);
		void RemoveOldEntries();
		void ListRules(bool listAll) const;
		void WriteChanges();

	private:
		void GetPassword(std::string&);
		bool OpenPolicyFile();
		void ClosePolicyFile();
		
		RuleFindResult FindUserRule(SecOption, RuleType, 
			const std::string&, std::size_t&, bool&) const;
		VecStrConstIt FindUserRuleHelper(const std::string&, bool&, bool&, bool&,
			SecOption&, bool&) const;
		bool IsSubDir(const std::string &needle, const std::string &haystack) const;
		std::optional<std::pair<VecStrConstIt, VecStrConstIt>> FindUserRulesInDir(const std::string&) const;
		void SortRules();
		
		const unsigned iterations = 1000;	//iterations for PBKDF2
		const unsigned TAG_SIZE = AES::BLOCKSIZE;
		const unsigned KEY_SIZE = AES::MAX_KEYLENGTH;
		ProtectedPtr<SecByteBlock, SecByteBlockSerializer> kdfSalt;
		ProtectedPtr<SecByteBlock, SecByteBlockSerializer> kdfHash;

		HANDLE policyFileHandle;
		const std::string policyFileName;
		const std::string_view policyFileHeader = "Policy Settings\n";
		ProtectedPtr<std::string, StringSerializer> policyData;
		
		std::string globalPolicySettings;

		std::vector<std::string> userRuleInfo;		//dirs the user entered to do work on
		std::vector<std::string> userRulePaths;		//extracted paths from userRuleInfo

		std::vector<std::string> updatedRules;		//rules that have been updated or switched
		std::vector<std::string> removedRules;		//rules that have been/to be removed

		std::vector<std::string> ruleInfo;			//data of already created rules
		std::vector<std::string> rulePaths;			//paths of created rules for searching
		
		bool rulesAdded = false;
		bool firstTimeRun = false;
		mutable bool passwordReset = false;
		bool policyDataModified = false;

		bool userRulesNotSorted = true;

		std::vector<std::string> executableTypes = {
			"ADE", "ADP", "APPLICATION", "BAS", "BAT", "BGI", "CHM", "CMD", "COM",
			"CPL", "CRT", "DIAGCAB", "DLL", "EXE", "HLP", "HTA", "INF", "INS",
			"ISP", "JS", "JSE", "LNK", "MDB", "MDE", "MSC", "MSI", "MSP", "MST",
			"OCX", "PCD", "PIF", "PS1", "PS2", "PSM", "REG", "SCR", "SCT", "SHS",
			"URL", "VB", "VBE", "VBS", "VBSCRIPT", "WSC", "XAML", "XBAP", "XPI" };
	};
}