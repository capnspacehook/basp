#include "DataFileManger.hpp"
#include "include\WinReg.hpp"
#include "Windows.h"

#include "include\Crypto++\pwdbased.h"
#include "include\Crypto++\filters.h"
#include "include\Crypto++\osrng.h"
#include "include\Crypto++\files.h"
#include "include\Crypto++\sha.h"
#include "include\Crypto++\gcm.h"
#include "include\Crypto++\hex.h"

#include <algorithm>
#include <exception>
#include <iostream>
#include <sstream>

using namespace std;
using namespace CryptoPP;
using namespace AppSecPolicy;
using namespace Protected_Ptr;
namespace fs = std::experimental::filesystem;

//attempt to open settings file and verify that key used to open encrypted file
//is correct, and that settings file has not been modified
bool DataFileManager::OpenPolicyFile()
{
	string temp;
	bool goodOpen = true;

	//attempt to decrypt file
	GCM<AES>::Decryption decryptor;
	decryptor.SetKeyWithIV(kdfHash->data(), KEY_SIZE, kdfHash->data() + KEY_SIZE, KEY_SIZE);
	kdfHash.ProtectMemory(true);

	AuthenticatedDecryptionFilter adf(decryptor, new StringSink(temp),
		AuthenticatedDecryptionFilter::MAC_AT_END, TAG_SIZE);
	FileSource encPolicyFile(policyFileName.c_str(), false);
	//skip part containing the salt
	encPolicyFile.Pump(KEY_SIZE);
	encPolicyFile.Attach(new Redirector(adf));
	encPolicyFile.PumpAll();

	//check if file header exists at beginning of file, if it doesn't the 
	//key used to decrypt the file is incorrect
	if (temp.substr(0, policyFileHeader.length()) != policyFileHeader)
		goodOpen = false;

	else
		if (!adf.GetLastResult())
		{
			goodOpen = false;
			cerr << "\nBASP's data has been tampered with, the integrity of both "
				<< "BASP's stored data and the rules in the registry cannot be verified. "
				<< "Extreme caution is advised.";
			exit(-1);
		}

	if (goodOpen)
	{
		//lock the settings file so that no other 
		//process/thread can read or modify it
		policyFileHandle = CreateFile(
			policyFileName.c_str(),
			GENERIC_READ | GENERIC_WRITE,
			NULL,
			nullptr,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			nullptr);

		*policyData = temp;
		istringstream iss(*policyData);

		//skip header 
		getline(iss, temp);
		//get global settings
		getline(iss, globalPolicySettings);

		if (getline(iss, temp))
		{
			//read in userRules
			bool rulesLeft = true;
			while (rulesLeft && (temp.back() == '*' || temp.back() == '#'))
			{
				if (temp.back() == '*')
					temp.pop_back();

				temp.pop_back();
				userRuleInfo.emplace_back(temp);
				userRulePaths.emplace_back(temp.substr(
					RULE_PATH_POS, temp.length()));

				rulesLeft = static_cast<bool>(getline(iss, temp));
			}

			//read in regular rules
			if (rulesLeft)
			{
				ruleInfo.emplace_back(temp + '\n');
				rulePaths.emplace_back(temp.substr(
					RULE_PATH_POS, temp.find("|{") - 4));

				while (getline(iss, temp))
				{
					ruleInfo.emplace_back(temp + '\n');
					rulePaths.emplace_back(temp.substr(
						RULE_PATH_POS, temp.find("|{") - 4));
				}
			}
		}

		ClosePolicyFile();
	}

	SecureZeroMemory(&temp, sizeof(temp));

	return goodOpen;
}

//closes and encryptes settings file
void DataFileManager::ClosePolicyFile()
{
	GCM<AES>::Encryption encryptor;
	encryptor.SetKeyWithIV(kdfHash->data(), KEY_SIZE, kdfHash->data() + KEY_SIZE, KEY_SIZE);
	kdfHash.ProtectMemory(true);
	
	//place salt unencrypted in beginning of file
	FileSink file(policyFileName.c_str());
	ArraySource as(*kdfSalt, kdfSalt->size(), true,
		new Redirector(file));
	kdfSalt.ProtectMemory(true);

	if (policyData->substr(0, policyFileHeader.length()) != policyFileHeader
		&& policyData->substr(0, KEY_SIZE) != string(KEY_SIZE, 'A'))
	{
		//prepend header and global policy settings
		policyData->insert(0, policyFileHeader);
		policyData->insert(policyFileHeader.length(), GetGlobalSettings() + '\n');

		//prepend dummy data that will be skipped
		policyData->insert(0, KEY_SIZE, 'A');
	}
	
	else if (policyData->substr(0, policyFileHeader.length()) == policyFileHeader)
	{
		//prepend dummy data that will be skipped
		policyData->insert(0, KEY_SIZE, 'A');
	}

	StringSource updatedData(*policyData, false);
	//skip part containing the salt
	updatedData.Pump(KEY_SIZE);
	updatedData.Attach(new AuthenticatedEncryptionFilter(
		encryptor, new Redirector(file), false, TAG_SIZE));
	updatedData.PumpAll();

	policyData.ProtectMemory(true);
}

//returns global policy data as in registry. If no global settings exist,
//default settings are set
string DataFileManager::GetCurrentPolicySettings() const
{
	using namespace winreg;

	try
	{
		string policySettings;
		RegKey policyKey(
			HKEY_LOCAL_MACHINE,
			R"(SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers)",
			KEY_READ | KEY_WRITE);
		
		auto values = policyKey.EnumValues();

		//global settings not yet set, set as defaults
		if (values.size() < 5)
		{
			policyKey.SetDwordValue("AuthenticodeEnabled", 0);
			policyKey.SetDwordValue("DefaultLevel", 0);
			policyKey.SetMultiStringValue("ExecutableTypes", executableTypes);
			policyKey.SetDwordValue("PolicyScope", 0);
			policyKey.SetDwordValue("TransparentEnabled", 1);
		}

		//read in global settings
		policySettings += to_string(policyKey.GetDwordValue("AuthenticodeEnabled"));
		policySettings += "|";
		
		DWORD defaultLevel = policyKey.GetDwordValue("DefaultLevel");
		if (defaultLevel == 262144)
			defaultLevel = 1;
		
		policySettings += to_string(defaultLevel);
		policySettings += "|";

		policySettings += to_string(policyKey.GetDwordValue("PolicyScope"));
		policySettings += "|";

		policySettings += to_string(policyKey.GetDwordValue("TransparentEnabled"));
		policySettings += "|";

		vector<string> exeTypes = policyKey.GetMultiStringValue("ExecutableTypes");
		for (const auto& type : exeTypes)
			policySettings += type + ",";

		policySettings.pop_back();

		return policySettings;
	}
	catch (const RegException &e)
	{
		cerr << '\n' << e.what();
	}
	catch (const exception &e)
	{
		cerr << '\n' << e.what();
	}
}

//searches list of created rules, returns status of search
RuleFindResult DataFileManager::FindRule(SecOption option, RuleType type,
	const string &path, RuleData &foundRuleData) const
{
	const SecOption findOp = option;
	const RuleType findType = type;
	RuleFindResult result = RuleFindResult::NO_MATCH;

	if (rulePaths.empty())
		return result;
	
	auto iterator = lower_bound(rulePaths.begin(), rulePaths.end(), path);
	
	if (iterator != rulePaths.end() && !(path < *iterator))
	{
		string foundRule = ruleInfo[distance(rulePaths.begin(), iterator)];
	
		foundRuleData = StringToRuleData(foundRule);

		option = get<SEC_OPTION>(foundRuleData);
		type = get<RULE_TYPE>(foundRuleData);

		if (findOp != option && findType != type)
			result = RuleFindResult::DIFF_OP_AND_TYPE;

		else if (findOp != option)
			result = RuleFindResult::DIFF_SEC_OP;

		else if (findType != type)
			result = RuleFindResult::DIFF_TYPE;

		else
			result = RuleFindResult::EXACT_MATCH;
	}

	return result;
}

//searches list of userRules, returns status of search. If rule is found, whether
//the found rule is a subdirectory of parent directory of another existing rule is 
//also specified to the caller
RuleFindResult DataFileManager::FindUserRule(SecOption option, RuleType type,
	const string &path, size_t &index, bool &parentDirDiffOp) const
{
	RuleFindResult result = RuleFindResult::NO_MATCH;

	if (userRulePaths.empty())
		return result;

	bool validRule = false;
	SecOption parentOp;
	bool parentDir = false;
	bool existingSubdir = false;
	bool nonExistingSubdir = false;
	const SecOption findOp = option;
	const RuleType findType = type;
	
	auto foundRule = FindUserRuleHelper(path, parentDir, nonExistingSubdir, existingSubdir,
		parentOp, validRule);

	if (validRule)
	{
		index = distance(userRulePaths.begin(), foundRule);

		string foundRuleInfo = userRuleInfo[index];

		option = static_cast<SecOption>(
			foundRuleInfo[SEC_OPTION_POS] - '0');

		type = static_cast<RuleType>(
			foundRuleInfo[RULE_TYPE_POS] - '0');

		if (option == SecOption::REMOVED)
		{
			if (existingSubdir)
				result = RuleFindResult::RM_SUBDIR;

			else
				result = RuleFindResult::REMOVED;
		}

		else if (findOp != option)
		{
			if (nonExistingSubdir)
			{
				if (findOp == SecOption::REMOVED)
					result = RuleFindResult::NO_EXIST_SUBDIR_TO_BE_RM;

				else
					result = RuleFindResult::NO_EXIST_SUBDIR_DIFF_OP;
			}

			else if (existingSubdir)
			{
				if (findOp == SecOption::REMOVED)
					result = RuleFindResult::EXIST_SUBDIR_TO_BE_RM;

				else
					result = RuleFindResult::EXIST_SUBDIR_DIFF_OP;
			}

			else if (parentDir)
			{
				if (findOp == SecOption::REMOVED)
					result = RuleFindResult::PARENT_DIR_TO_BE_RM;

				else
					result = RuleFindResult::PARENT_DIR_DIFF_OP;
			}

			else
				result = RuleFindResult::DIFF_SEC_OP;
		}

		else if (findType != type)
			result = RuleFindResult::DIFF_TYPE;

		else if (findOp != option && findType != type)
			result = RuleFindResult::DIFF_OP_AND_TYPE;

		else
		{
			if (nonExistingSubdir)
				result = RuleFindResult::NO_EXIST_SUBDIR_SAME_OP;

			else if (existingSubdir)
				result = RuleFindResult::EXIST_SUBDIR_SAME_OP;

			else if (parentDir)
				result = RuleFindResult::PARENT_DIR_SAME_OP;

			else
				result = RuleFindResult::EXACT_MATCH;
		}

		if (nonExistingSubdir || existingSubdir)
		{
			if (option == SecOption::REMOVED && parentOp != findOp)
				parentDirDiffOp = true;

			else if (result != RuleFindResult::RM_SUBDIR && parentOp != option)
				parentDirDiffOp = true;
		}
	}

	return result;
}

VecStrConstIt DataFileManager::FindUserRuleHelper(const string &path, bool &parentDir,
	bool &nonExistingSubdir, bool &existingSubdir, SecOption &parentOp,  bool &validRule) const
{
	bool exactRule = false;
	VecStrConstIt foundRule;

	const auto exactSearchResult = lower_bound(userRulePaths.begin(), userRulePaths.end(), path);

	if (exactSearchResult != userRulePaths.end() && *exactSearchResult == path)
	{
		exactRule = true;
		foundRule = exactSearchResult;
		validRule = true;
	}

	const auto subDirSearchResult = lower_bound(userRulePaths.begin(), userRulePaths.end(), path,
		[](const string &str1, const string &str2) noexcept
		{
			return str1 < str2.substr(0, str1.length());
		});

	if (subDirSearchResult != userRulePaths.end() && !(path < *subDirSearchResult) &&
		*subDirSearchResult != path && IsSubDir(path, *subDirSearchResult))
	{
		if (exactRule)
		{
			existingSubdir = true;
			foundRule = exactSearchResult;
		}

		else
		{
			nonExistingSubdir = true;
			foundRule = subDirSearchResult;
		}

		parentOp = static_cast<SecOption>(
			userRuleInfo[distance(userRulePaths.begin(), subDirSearchResult)][SEC_OPTION] - '0');

		validRule = true;
	}

	else 
	{
		const auto parentSearchResult = lower_bound(userRulePaths.begin(), userRulePaths.end(), path,
			[](const string &str1, const string &str2) noexcept
			{
				if (str1 == str2)
					return true;

				return str1.substr(0, str2.length()) < str2;
			});

		if (parentSearchResult != userRulePaths.end() && path < *parentSearchResult &&
			*parentSearchResult != path && IsSubDir(*parentSearchResult, path))
		{
			parentDir = true;
			parentOp = static_cast<SecOption>(
				userRuleInfo[distance(userRulePaths.begin(), parentSearchResult)][SEC_OPTION] - '0');

			foundRule = parentSearchResult;
			validRule = true;
		}
	}

	return foundRule;
}

//returns true if 'needle' is a subdir of 'haystack'
bool DataFileManager::IsSubDir(const string &needle, const string &haystack) const
{
	fs::path needlePath(needle);
	const auto needleParentNum = distance(needlePath.begin(), needlePath.end()) - 2;

	for (int i = 0; i < needleParentNum; i++)
	{
		needlePath = move(needlePath.parent_path());
		if (needlePath.string() == haystack)
			return true;
	}

	return false;
}

vector<RuleData> DataFileManager::FindRulesInDir(const string &path) const
{
	vector<RuleData> rulesInDir;

	auto foundRulesBegin = lower_bound(rulePaths.begin(), rulePaths.end(), path);

	auto foundRulesEnd = upper_bound(foundRulesBegin, rulePaths.end(), path,
		[](const string &str1, const string &str2) noexcept
		{
			return str1 < str2.substr(0, str1.length());
		});

	if ((foundRulesBegin != rulePaths.end() || foundRulesEnd != rulePaths.end())
		&& (foundRulesBegin != rulePaths.begin() || foundRulesEnd != rulePaths.begin()))
	{
		auto ruleInfoRange = make_pair(
			ruleInfo.begin() + distance(rulePaths.begin(), foundRulesBegin),
			ruleInfo.begin() + distance(rulePaths.begin(), foundRulesEnd));

		rulesInDir.reserve(distance(foundRulesBegin, foundRulesEnd));
		for (auto it = ruleInfoRange.first; it != ruleInfoRange.second; ++it)
			rulesInDir.emplace_back(StringToRuleData(*it));
	}

	return rulesInDir;
}

optional<pair<VecStrConstIt, VecStrConstIt>> DataFileManager::FindUserRulesInDir(const string &path) const
{
	bool subDirsExist = true;
	optional<pair<VecStrConstIt, VecStrConstIt>> rulesInDir;
	
	auto foundRulesBegin = lower_bound(userRulePaths.begin(), userRulePaths.end(), path);

	if (*foundRulesBegin == path)
	{
		if (next(foundRulesBegin) != userRulePaths.end() && IsSubDir(*next(foundRulesBegin), path))
			advance(foundRulesBegin, 1);

		else
			subDirsExist = false;
	}
	
	if (subDirsExist)
	{
		auto foundRulesEnd = upper_bound(foundRulesBegin, userRulePaths.end(), path,
			[](const string &str1, const string &str2) noexcept
			{
				return str1 < str2.substr(0, str1.length());
			});

		if (foundRulesBegin == foundRulesEnd && foundRulesEnd != userRulePaths.end())
			advance(foundRulesEnd, 1);

		if ((foundRulesBegin != userRulePaths.end() || foundRulesEnd != userRulePaths.end())
			&& (foundRulesBegin != userRulePaths.begin() || foundRulesEnd != userRulePaths.begin()))
		{
			rulesInDir.emplace(make_pair(
				userRuleInfo.begin() + distance(userRulePaths.begin(), foundRulesBegin),
				userRuleInfo.begin() + distance(userRulePaths.begin(), foundRulesEnd)));
		}
	}

	return rulesInDir;
}

RuleData DataFileManager::StringToRuleData(const string& ruleStr)
{
	string temp;
	string hash;
	RuleData ruleData;
	istringstream iss(ruleStr);

	getline(iss, temp, '|');
	get<SEC_OPTION>(ruleData) = static_cast<SecOption>(
		static_cast<int>((temp.front() - '0')));

	getline(iss, temp, '|');
	get<RULE_TYPE>(ruleData) = static_cast<RuleType>(
		static_cast<int>((temp.front() - '0')));

	getline(iss, temp, '|');
	get<FILE_LOCATION>(ruleData) = temp;

	getline(iss, temp, '|');
	get<RULE_GUID>(ruleData) = temp;

	getline(iss, temp, '|');
	get<FRIENDLY_NAME>(ruleData) = temp;

	getline(iss, temp, '|');
	get<ITEM_SIZE>(ruleData) = stoull(temp);

	getline(iss, temp, '|');
	get<LAST_MODIFIED>(ruleData) = stoull(temp);

	getline(iss, temp, '|');
	StringSource(temp, true,
		new HexDecoder(new StringSink(hash)));

	for (const auto &MD5byte : hash)
		get<ITEM_DATA>(ruleData).emplace_back(MD5byte);

	hash.clear();
	getline(iss, temp, '|');
	StringSource(temp, true,
		new HexDecoder(new StringSink(hash)));

	for (const auto &SHAbyte : hash)
		get<SHA256_HASH>(ruleData).emplace_back(SHAbyte);

	return ruleData;
}

string DataFileManager::RuleDataToString(const RuleData& ruleData)
{
	auto hashToStr =
		[](const auto& hash)
		{
			string hashStr;
			string hexStr;
			for (const auto byte : hash)
				hashStr += byte;

			StringSource(hashStr, true,
				new HexEncoder(new StringSink(hexStr)));
			return hexStr;
		};

	return to_string(static_cast<int>(get<SEC_OPTION>(ruleData))) + '|' +
		to_string(static_cast<int>(get<RULE_TYPE>(ruleData))) + '|' + 
		get<FILE_LOCATION>(ruleData) + '|' + get<RULE_GUID>(ruleData) + '|' +
		get<FRIENDLY_NAME>(ruleData) + '|' + to_string(get<ITEM_SIZE>(ruleData)) + '|' + 
		to_string(get<LAST_MODIFIED>(ruleData)) + '|' +
		hashToStr(get<ITEM_DATA>(ruleData)) + '|' + hashToStr(get<SHA256_HASH>(ruleData)) + '\n';
}

void DataFileManager::SortRules()
{
	if (userRulesNotSorted)
	{
		sort(userRuleInfo.begin(), userRuleInfo.end(),
			[](const string &str1, const string &str2)
			{
				return str1.substr(RULE_PATH_POS,
					str1.length())
					< str2.substr(RULE_PATH_POS,
						str2.length());
			});

		userRulePaths.clear();
		for (const auto& rule : userRuleInfo)
		{
			userRulePaths.emplace_back(rule.substr(RULE_PATH_POS,
				rule.length()));
		}

		userRulesNotSorted = false;
	}

	if (rulesAdded)
	{
		sort(ruleInfo.begin(), ruleInfo.end(),
			[](const string &str1, const string &str2)
			{
				return str1.substr(RULE_PATH_POS,
					str1.find("|{") - 4)
					< str2.substr(RULE_PATH_POS,
						str2.find("|{") - 4);
			});

		rulePaths.clear();
		for (const auto& rule : ruleInfo)
		{
			rulePaths.emplace_back(rule.substr(RULE_PATH_POS,
				rule.find("|{") - 4));
		}

		rulesAdded = false;
	}
}

vector<RuleData> DataFileManager::GetDeletedFiles(const vector<RuleData>& ruleData)
{
	vector<RuleData> processedRules;
	vector<RuleData> currentRules;
	vector<RuleData> deletedFiles;

	processedRules.reserve(ruleData.size());
	for (const auto &rule : ruleData)
		processedRules.emplace_back(rule);

	for (const auto &rule : updatedRules)
	{
		auto temp = FindRulesInDir(rule);
		currentRules.insert(currentRules.begin(),
			temp.begin(), temp.end());
	}

	sort(currentRules.begin(), currentRules.end(),
		[](const RuleData &lhs, const RuleData &rhs) noexcept
		{
			return get<FILE_LOCATION>(lhs) < get<FILE_LOCATION>(rhs);
		});

	sort(processedRules.begin(), processedRules.end(),
		[](const RuleData &lhs, const RuleData &rhs) noexcept
		{
			return get<FILE_LOCATION>(lhs) < get<FILE_LOCATION>(rhs);
		});

	set_difference(
		currentRules.begin(), currentRules.end(),
		processedRules.begin(), processedRules.end(),
		back_inserter(deletedFiles),
		[](const RuleData &lhs, const RuleData &rhs) noexcept
		{
			return get<FILE_LOCATION>(lhs) < get<FILE_LOCATION>(rhs);
		});

	return deletedFiles;
}

void DataFileManager::UpdateUserRules(const vector<UserRule> &ruleNames, bool rulesRemoved)
{
	SecOption option;
	RuleType type;
	string location;
	size_t index;

	userRulesNotSorted = false;
	bool parentDiffOp = false;

	for (const auto& rule : ruleNames)
	{
		option = static_cast<SecOption>(get<SEC_OPTION>(rule));
		type = static_cast<RuleType>(get<RULE_TYPE>(rule));
		location = get<FILE_LOCATION>(rule);

		SortRules();

		const RuleFindResult result = FindUserRule(option, type, location, index, parentDiffOp);

		if (result == RuleFindResult::NO_MATCH && !rulesRemoved)
		{
			userRuleInfo.emplace_back(to_string(static_cast<int>(option))
				+ '|' + to_string(static_cast<int>(type))
				+ '|' + location);
			
			userRulesNotSorted = true;
		}

		else if (result != RuleFindResult::NO_MATCH
			&& result != RuleFindResult::RM_SUBDIR
			&& result != RuleFindResult::REMOVED
			&& rulesRemoved)
		{
			removedRules.emplace_back(location);

			if (result == RuleFindResult::NO_EXIST_SUBDIR_TO_BE_RM)
			{
				userRulesNotSorted = true;

				userRuleInfo.emplace_back(
					to_string(static_cast<int>(SecOption::REMOVED))
					+ '|' + to_string(static_cast<int>(type))
					+ '|' + location);
			}

			else if (result == RuleFindResult::EXIST_SUBDIR_TO_BE_RM)
				userRuleInfo[index][SEC_OPTION] = static_cast<char>(option) + '0';

			else if (result == RuleFindResult::PARENT_DIR_TO_BE_RM)
			{
				auto deletedRules = FindUserRulesInDir(location);

				if (deletedRules)
				{
					const auto start = distance(userRuleInfo.cbegin(), deletedRules->first);
					const auto end = distance(userRuleInfo.cbegin(), deletedRules->second);

					for (auto i = start; i < end; i++)
						userRuleInfo[i][SEC_OPTION] = static_cast<char>(option) + '0';
				}
			}
				
			else
			{
				userRuleInfo.erase(userRuleInfo.begin() + index);
				userRulesNotSorted = true;
			}
		}

		else if (result == RuleFindResult::PARENT_DIR_SAME_OP 
			|| result == RuleFindResult::PARENT_DIR_DIFF_OP)
		{
			userRuleInfo.emplace_back(to_string(static_cast<int>(option))
				+ '|' + to_string(static_cast<int>(type))
				+ '|' + location);

			auto subDirs = FindUserRulesInDir(location);

			if (subDirs)
			{
				userRuleInfo.erase(subDirs->first, subDirs->second);
				userRulesNotSorted = true;
			}
		}

		else if (result == RuleFindResult::NO_EXIST_SUBDIR_DIFF_OP)
		{
			updatedRules.emplace_back(location);
			userRuleInfo.emplace_back(to_string(static_cast<int>(option))
				+ '|' + to_string(static_cast<int>(type))
				+ '|' + location);

			userRulesNotSorted = true;
		}

		else if (result == RuleFindResult::EXIST_SUBDIR_DIFF_OP)
		{
			updatedRules.emplace_back(location);

			if (parentDiffOp)
			{
				userRuleInfo.erase(userRuleInfo.begin() + index);
				userRulesNotSorted = true;
			}

			else
				userRuleInfo[index][SEC_OPTION] = static_cast<char>(option) + '0';
		}

		else if (result == RuleFindResult::DIFF_SEC_OP)
		{
			updatedRules.emplace_back(location);
			userRuleInfo[index][SEC_OPTION] = static_cast<char>(option) + '0';

			//make sure we remove any subdirs if they exist
			auto subDirs = FindUserRulesInDir(location);

			if (subDirs)
			{
				userRuleInfo.erase(subDirs->first, subDirs->second);
				userRulesNotSorted = true;
			}
		}

		else if (result == RuleFindResult::RM_SUBDIR)
		{
			if (parentDiffOp)
				userRuleInfo[index][SEC_OPTION] = static_cast<char>(option) + '0';

			else
			{
				userRuleInfo.erase(userRuleInfo.begin() + index);
				userRulesNotSorted = true;
			}
		}

		else if (result == RuleFindResult::REMOVED)
			userRuleInfo[index][SEC_OPTION] = static_cast<char>(option) + '0';

		else if (!rulesRemoved)
			updatedRules.emplace_back(location);
	}
}

void DataFileManager::InsertNewEntries(const vector<RuleDataPtr>& ruleData)
{
	try
	{
		if (!ruleData.empty())
			rulesAdded = true;

		for (const auto& rule : ruleData)
		{
			rulePaths.emplace_back(get<FILE_LOCATION>(*rule));
			ruleInfo.emplace_back(RuleDataToString(*rule));
		}
	}
	catch (const exception &e)
	{
		cerr << e.what() << '\n';
	}
}

void DataFileManager::UpdateEntries(SecOption option,
	const vector<RuleDataPtr>& ruleData)
{
	SortRules();

	for (const auto &updatedRule : ruleData)
	{
		auto iterator = lower_bound(
			rulePaths.begin(), rulePaths.end(), get<FILE_LOCATION>(*updatedRule));

		if (iterator != rulePaths.end() && !(get<FILE_LOCATION>(*updatedRule) < *iterator))
		{
			if (get<MOD_STATUS>(*updatedRule) == ModificationType::UPDATED)
				ruleInfo[distance(rulePaths.begin(), iterator)] = RuleDataToString(*updatedRule);

			else if (get<MOD_STATUS>(*updatedRule) == ModificationType::SWITCHED)
				ruleInfo[distance(rulePaths.begin(), iterator)][SEC_OPTION] = static_cast<char>(option) + '0';
		}

		else
			cerr << "Updating entries failed: rule not found\n";
	}
}

void DataFileManager::RemoveDeletedFiles(const vector<RuleData> &deletedFiles)
{
	SortRules();
	
	for (const auto &deletedFile : deletedFiles)
	{
		auto foundRule = lower_bound(rulePaths.begin(), rulePaths.end(),
			get<FILE_LOCATION>(deletedFile));

		const auto removedIndex = distance(rulePaths.begin(), foundRule);
		rulePaths.erase(foundRule);
		ruleInfo.erase(ruleInfo.begin() + removedIndex);
	}
}

void DataFileManager::RemoveOldEntries()
{
	SortRules();

	bool allRulesRemoved = true;
	for (const auto &rule : userRuleInfo)
	{
		if (rule.front() != static_cast<char>(SecOption::REMOVED) + '0')
		{
			allRulesRemoved = false;
			break;
		}
	}

	if (allRulesRemoved)
	{
		ruleInfo.clear();
		rulePaths.clear();
		userRuleInfo.clear();
		userRulePaths.clear();
	}

	else
	{
		for (const auto &rule : removedRules)
		{
			auto removedRulesBegin = lower_bound(rulePaths.begin(), rulePaths.end(), rule);

			auto removedRulesEnd = upper_bound(removedRulesBegin, rulePaths.end(), rule,
				[](const string &str1, const string &str2) noexcept
				{
					return str1 < str2.substr(0, str1.length());
				});

			auto ruleInfoRange = make_pair(
				ruleInfo.begin() + distance(rulePaths.begin(), removedRulesBegin),
				ruleInfo.begin() + distance(rulePaths.begin(), removedRulesEnd));

			rulePaths.erase(removedRulesBegin, removedRulesEnd);
			ruleInfo.erase(ruleInfoRange.first, ruleInfoRange.second);
		}
	}
}

void DataFileManager::WriteChanges()
{
	SortRules();

	policyData->clear();

	for (const auto& line : userRuleInfo)
	{
		if (fs::is_directory(
			line.substr(RULE_PATH_POS, line.length())))
			*policyData += line + R"(\*)" + '\n';

		else 
			*policyData += line + '#' + '\n';
	}
		

	for (const auto& line : ruleInfo)
		*policyData += line;

	policyDataModified = true;
}

void DataFileManager::VerifyPassword(string &&guessPwd)
{
	if (fs::exists(policyFileName.c_str()))
		CheckPassword(move(guessPwd));
	else
	{
		firstTimeRun = true;
		SetNewPassword(move(guessPwd));
	}
}

void DataFileManager::CheckPassword(string& guessPwd)
{
	bool cmdPwd = true;
	bool validPwd = false;

	if (guessPwd.empty())
		cmdPwd = false;
	
	//get salt from beginning of file
	FileSource encPolicyFile(policyFileName.c_str(), false);
	encPolicyFile.Attach(new ArraySink(*kdfSalt, kdfSalt->size()));
	encPolicyFile.Pump(KEY_SIZE);
	
	do
	{
		if (!cmdPwd)
		{
			cout << "Enter the password:\n";
			GetPassword(guessPwd);
		}

		cout << "Verifying password...";

		PKCS5_PBKDF2_HMAC<SHA256> kdf;
		kdf.DeriveKey(
			kdfHash->data(),
			kdfHash->size(),
			0,
			(BYTE*)guessPwd.data(),
			guessPwd.size(),
			kdfSalt->data(),
			kdfSalt->size(),
			iterations);

		kdfHash.ProtectMemory(true);
		kdfSalt.ProtectMemory(true);

		validPwd = OpenPolicyFile();

		if (validPwd)
			cout << "done\n";

		else
		{
			cout << "\nInvalid password entered\n";

			if (cmdPwd)
				exit(-1);
		}

	} while (!validPwd);

	SecureZeroMemory(&guessPwd, sizeof(guessPwd));
}

void DataFileManager::SetNewPassword(string& guessPwd)
{
	string newPass1;
	if (guessPwd.empty())
	{
		string newPass2;
		bool passesMismatch = true;

		do
		{
			cout << "Enter your new password:\n";
			GetPassword(newPass1);

			cout << "Enter it again:\n";
			GetPassword(newPass2);

			if (newPass1 != newPass2)
				cout << "Passwords do not match. Please enter again.\n";
			else
				passesMismatch = false;
		} while (passesMismatch);

		SecureZeroMemory(&newPass2, sizeof(newPass2));
	}

	else
	{
		newPass1 = move(guessPwd);
		SecureZeroMemory(&guessPwd, sizeof(guessPwd));
	}

	cout << "Computing new password hash...";

	AutoSeededRandomPool prng;
	prng.GenerateBlock(*kdfSalt, KEY_SIZE);

	PKCS5_PBKDF2_HMAC<SHA256> kdf;
	kdf.DeriveKey(
		kdfHash->data(),
		kdfHash->size(),
		0,
		(BYTE*)newPass1.data(),
		newPass1.size(),
		kdfSalt->data(),
		kdfSalt->size(),
		iterations);

	SecureZeroMemory(&newPass1, sizeof(newPass1));

	kdfHash.ProtectMemory(true);
	kdfSalt.ProtectMemory(true);

	winreg::RegKey policySettings(
		HKEY_LOCAL_MACHINE,
		"SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers",
		KEY_WRITE);

	policySettings.SetMultiStringValue("ExecutableTypes", executableTypes);

	passwordReset = true;

	cout << "done\n";;
	ClosePolicyFile();
}

void DataFileManager::GetPassword(string &password)
{
	//set console to not show typed password
	HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
	DWORD mode = 0;
	GetConsoleMode(hStdin, &mode);
	SetConsoleMode(hStdin, mode & (~ENABLE_ECHO_INPUT));
	
	getline(cin, password);

	//reset console to normal
	SetConsoleMode(hStdin, mode);
}

void DataFileManager::ListRules(bool listAll) const
{
	constexpr char removed = static_cast<char>(SecOption::REMOVED) + '0';
	constexpr char whiteList = static_cast<char>(SecOption::WHITELIST) + '0';
	constexpr char blackList = static_cast<char>(SecOption::BLACKLIST) + '0';
	
	auto sortedRules = [&]()
	{
		if (listAll)
		{
			auto tempVec = ruleInfo;
			sort(tempVec.begin(), tempVec.end(),
				[&removed](const string &str1, const string &str2)
				{
					if (str1[SEC_OPTION] != str2[SEC_OPTION])
						return str1[SEC_OPTION] > str2[SEC_OPTION];

					fs::path path1(str1.substr(
						RULE_PATH_POS, str1.find("|{") - 4));

					fs::path path2(str2.substr(
						RULE_PATH_POS, str2.find("|{") - 4));

					if (path1.parent_path() != path2.parent_path())
						return path1.parent_path() < path2.parent_path();

					else
						return path1.filename() < path2.filename();
				});

			return tempVec;
		}

		else
		{
			auto tempVec = userRuleInfo;
			sort(tempVec.begin(), tempVec.end(),
				[&removed](const string &str1, const string &str2)
				{
					if ((str1[SEC_OPTION] != removed && str2[SEC_OPTION] != removed)
						&& (str1[SEC_OPTION] != str2[SEC_OPTION]))
						return str1[SEC_OPTION] > str2[SEC_OPTION];

					fs::path path1(str1.substr(RULE_PATH_POS,
						str1.length()));

					fs::path path2(str2.substr(RULE_PATH_POS,
						str2.length()));

					if (path1.parent_path() != path2.parent_path())
						return path1.parent_path() < path2.parent_path();

					else
						return path1.filename() < path2.filename();
				});

			for (auto &rule : tempVec)
			{
				if (fs::is_directory(
					rule.substr(RULE_PATH_POS, rule.length())))
					rule += R"(\*)";
			}

			return tempVec;
		}
	} ();

	if (!sortedRules.empty())
	{
		unsigned index = 0;
		unsigned numWhitelistingRules = 0;
		
		if (sortedRules[0][0] == whiteList)
		{
			cout << "\nAllowed rules:";
			for (; index < sortedRules.size(); index++)
			{
				if (sortedRules[index][SEC_OPTION] == whiteList)
				{
					if (listAll)
					{
						cout << '\n' << sortedRules[index].substr(
							RULE_PATH_POS, sortedRules[index].find("|{") - 4);
					}

					else
					{
						cout << '\n' << sortedRules[index].substr(RULE_PATH_POS,
							sortedRules[index].length());
					}
				}

				else if (!listAll && sortedRules[index][SEC_OPTION] == removed)
					cout << "\nExcept: " << sortedRules[index].substr(RULE_PATH_POS,
						sortedRules[index].length());

				else
					break;
			}

			numWhitelistingRules = index;
		}

		if (numWhitelistingRules < sortedRules.size() && sortedRules[index][0] == blackList)
		{
			if (numWhitelistingRules)
				cout << '\n';

			cout << "\nDenied rules:";
			for (; index < sortedRules.size(); index++)
			{
				if (sortedRules[index][SEC_OPTION] == blackList)
				{
					if (listAll)
					{
						cout << '\n' << sortedRules[index].substr(
							RULE_PATH_POS, sortedRules[index].find("|{") - 4);
					}

					else
					{
						cout << '\n' << sortedRules[index].substr(RULE_PATH_POS,
							sortedRules[index].length());
					}
				}

				else if (!listAll && sortedRules[index][SEC_OPTION] == removed)
					cout << "\nExcept: " << sortedRules[index].substr(RULE_PATH_POS,
						sortedRules[index].length());

				else
					break;
			}
		}

		cout << '\n';

		if (listAll)
		{
			if (numWhitelistingRules > 0)
				cout << "\nNumber of allowed rules: " << numWhitelistingRules;

			if (index - numWhitelistingRules > 0)
				cout << "\nNumber of denied rules:  " << index - numWhitelistingRules;

			cout << "\nTotal number of rules:   " << index << '\n';
		}
	}

	else
		cout << "\nCannot list rules, no rules have been created\n";
}