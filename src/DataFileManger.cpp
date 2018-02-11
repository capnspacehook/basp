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

bool DataFileManager::OpenPolicyFile()
{
	string temp;
	bool goodOpen = true;

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

	if (temp.substr(0, policyFileHeader.length()) != policyFileHeader)
		goodOpen = false;

	else
		if (!adf.GetLastResult())
		{
			goodOpen = false;
			cerr << "File modified!" << '\n';
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
		temp.clear();

		istringstream iss(*policyData);

		//skip header 
		getline(iss, temp);
		//get global settings
		getline(iss, globalPolicySettings);

		if (getline(iss, temp))
		{
			while (temp.back() == '*')
			{
				temp.pop_back();
				userRuleInfo.emplace_back(temp);
				userRulePaths.emplace_back(temp.substr(
					RULE_PATH_POS, temp.length()));

				getline(iss, temp);
			}

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

		ClosePolicyFile();
	}

	SecureZeroMemory(&temp, sizeof(temp));

	return goodOpen;
}

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
		policyData->insert(policyFileHeader.length(), GetCurrentPolicySettings() + '\n');

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

string DataFileManager::GetCurrentPolicySettings() const
{
	using namespace winreg;

	try
	{
		string policySettings;
		RegKey policyKey(
			HKEY_LOCAL_MACHINE,
			"SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers",
			KEY_READ | KEY_WRITE);
		
		auto values = policyKey.EnumValues();

		if (values.size() < 5)
		{
			policyKey.SetDwordValue("AuthenticodeEnabled", 0);
			policyKey.SetDwordValue("DefaultLevel", 0);
			policyKey.SetMultiStringValue("ExecutableTypes", executableTypes);
			policyKey.SetDwordValue("PolicyScope", 0);
			policyKey.SetDwordValue("TransparentEnabled", 1);
		}

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
		cout << e.what() << '\n';
	}
	catch (const exception &e)
	{
		cout << e.what() << '\n';
	}
}

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

RuleFindResult DataFileManager::FindUserRule(SecOption option, RuleType type,
	const string &path, size_t &index, bool &parentDirDiffOp) const
{
	bool validRule = false;
	
	SecOption parentOp;
	bool nonExistingSubdir = false;
	const SecOption findOp = option;
	const RuleType findType = type;
	RuleFindResult result = RuleFindResult::NO_MATCH;

	if (userRulePaths.empty())
		return result;

	vector<string>::const_iterator foundRule;

	auto subDirSearchResult = lower_bound(userRulePaths.begin(), userRulePaths.end(), path,
		[&path](string const& str1, string const& str2)
		{
			// compare UP TO the length of the prefix and no farther
			if (auto cmp = strncmp(str1.data(), str2.data(), path.size()))
				return cmp > 0;

			// The strings are equal to the length of the suffix so
			// behave as if they are equal. That means s1 < s2 == false
			return false;
		});

	if (subDirSearchResult != userRulePaths.end() && !(path < *subDirSearchResult))
	{
		if (*subDirSearchResult != path)
		{
			nonExistingSubdir = true;
			parentOp = static_cast<SecOption>(
				userRuleInfo[distance(userRulePaths.begin(), subDirSearchResult)][SEC_OPTION] - '0');
		}

		foundRule = subDirSearchResult;
		validRule = true;
	}

	if (validRule)
	{
		bool existingSubdir = false;

		auto exactSearchResult = lower_bound(userRulePaths.begin(), userRulePaths.end(), path);

		if (exactSearchResult != userRulePaths.end() && !(path < *exactSearchResult))
		{
			if (subDirSearchResult != exactSearchResult)
			{
				foundRule = exactSearchResult;
				existingSubdir = true;
			}

			nonExistingSubdir = false;
		}

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

			else
				result = RuleFindResult::EXACT_MATCH;
		}

		if (nonExistingSubdir || existingSubdir)
		{
			if (option == SecOption::REMOVED && parentOp != findOp)
				parentDirDiffOp = true;

			else if (parentOp != option)
				parentDirDiffOp = true;
		}
	}

	return result;
}

vector<RuleData> DataFileManager::FindRulesInDir(const string &path) const
{
	vector<RuleData> rulesInDir;

	auto removedRulesBegin = lower_bound(rulePaths.begin(), rulePaths.end(), path);

	auto removedRulesEnd = upper_bound(removedRulesBegin, rulePaths.end(), path,
		[&path](string const& str1, string const& str2)
		{
			// compare UP TO the length of the prefix and no farther
			if (auto cmp = strncmp(str1.data(), str2.data(), path.size()))
				return cmp < 0;

			// The strings are equal to the length of the prefix so
			// behave as if they are equal. That means s1 < s2 == false
			return false;
		});

	if ((removedRulesBegin != rulePaths.end() || removedRulesEnd != rulePaths.end())
		&& (removedRulesBegin != rulePaths.begin() || removedRulesEnd != rulePaths.begin()))
	{
		auto ruleInfoRange = make_pair(
			ruleInfo.begin() + distance(rulePaths.begin(), removedRulesBegin),
			ruleInfo.begin() + distance(rulePaths.begin(), removedRulesEnd));

		rulesInDir.reserve(distance(removedRulesBegin, removedRulesEnd));
		for (auto it = ruleInfoRange.first; it != ruleInfoRange.second; ++it)
			rulesInDir.emplace_back(StringToRuleData(*it));
	}

	return rulesInDir;
}

RuleData DataFileManager::StringToRuleData(const string& ruleStr) const
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
	temp.pop_back();
	StringSource(temp, true,
		new HexDecoder(new StringSink(hash)));

	for (const auto &SHAbyte : hash)
		get<SHA256_HASH>(ruleData).emplace_back(SHAbyte);

	return ruleData;
}

string DataFileManager::RuleDataToString(const RuleData& ruleData) const
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
		hashToStr(get<ITEM_DATA>(ruleData)) + '|' + hashToStr(get<SHA256_HASH>(ruleData)) + '\n';;
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
		rulesNotSorted = false;
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
		[](const RuleData &lhs, const RuleData &rhs)
		{
			return get<FILE_LOCATION>(lhs) < get<FILE_LOCATION>(rhs);
		});

	sort(processedRules.begin(), processedRules.end(),
		[](const RuleData &lhs, const RuleData &rhs)
		{
			return get<FILE_LOCATION>(lhs) < get<FILE_LOCATION>(rhs);
		});

	set_difference(
		currentRules.begin(), currentRules.end(),
		processedRules.begin(), processedRules.end(),
		back_inserter(deletedFiles),
		[](const RuleData &lhs, const RuleData &rhs)
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

	rulesNotSorted = false;
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
			rulesNotSorted = true;
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
				
			else
				userRuleInfo.erase(userRuleInfo.begin() + index);
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
				userRuleInfo.erase(userRuleInfo.begin() + index);

			else
				userRuleInfo[index][SEC_OPTION] = static_cast<char>(option) + '0';
		}

		else if (result == RuleFindResult::DIFF_SEC_OP)
		{
			updatedRules.emplace_back(location);
			userRuleInfo[index][SEC_OPTION] = static_cast<char>(option) + '0';
		}

		else if (result == RuleFindResult::RM_SUBDIR)
		{
			if (parentDiffOp)
				userRuleInfo[index][SEC_OPTION] = static_cast<char>(option) + '0';

			else 
				userRuleInfo.erase(userRuleInfo.begin() + index);
		}

		else if (result == RuleFindResult::REMOVED)
			userRuleInfo[index][SEC_OPTION] = static_cast<char>(option) + '0';

		else 
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

	for (const auto &rule : removedRules)
	{
		auto removedRulesBegin = lower_bound(rulePaths.begin(), rulePaths.end(), rule);

		auto removedRulesEnd = upper_bound(removedRulesBegin, rulePaths.end(), rule,
			[&rule](string const& str1, string const& str2)
			{
				// compare UP TO the length of the prefix and no farther
				if (auto cmp = strncmp(str1.data(), str2.data(), rule.size()))
					return cmp < 0;

				// The strings are equal to the length of the prefix so
				// behave as if they are equal. That means s1 < s2 == false
				return false;
			});

		auto ruleInfoRange = make_pair(
			ruleInfo.begin() + distance(rulePaths.begin(), removedRulesBegin),
			ruleInfo.begin() + distance(rulePaths.begin(), removedRulesEnd));

		rulePaths.erase(removedRulesBegin, removedRulesEnd);
		ruleInfo.erase(ruleInfoRange.first, ruleInfoRange.second);
	}
}

void DataFileManager::WriteChanges()
{
	if (userRulesNotSorted)
		sort(userRuleInfo.begin(), userRuleInfo.end(),
			[](const string &str1, const string &str2)
			{
				return str1.substr(RULE_PATH_POS,
					str1.length())
					< str2.substr(RULE_PATH_POS,
						str2.length());
			});

	if (rulesNotSorted)
	{
		sort(ruleInfo.begin(), ruleInfo.end(),
			[](const string &str1, const string &str2)
			{
				return str1.substr(RULE_PATH_POS,
					str1.find("|{") - 4)
					< str2.substr(RULE_PATH_POS,
					str2.find("|{") - 4);
			});
	}

	policyData->clear();

	for (const auto& line : userRuleInfo)
		*policyData += line + '*' + '\n';;

	for (const auto& line : ruleInfo)
		*policyData += line;

	policyDataModified = true;
}

void DataFileManager::VerifyPassword(string& guessPwd)
{
	if (fs::exists(policyFileName))
		CheckPassword(guessPwd);
	else
		SetNewPassword();

	cout << '\n';
}

void DataFileManager::CheckPassword(string& guessPwd)
{
	bool validPwd;
	bool cmdPwd = true;

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
			(byte*)guessPwd.data(),
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

void DataFileManager::SetNewPassword()
{
	string newPass1, newPass2;
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

	cout << "Computing new password hash...";
	SecureZeroMemory(&newPass1, sizeof(newPass1));

	AutoSeededRandomPool prng;
	prng.GenerateBlock(*kdfSalt, KEY_SIZE);

	PKCS5_PBKDF2_HMAC<SHA256> kdf;
	kdf.DeriveKey(
		kdfHash->data(),
		kdfHash->size(),
		0,
		(byte*)newPass2.data(),
		newPass2.size(),
		kdfSalt->data(),
		kdfSalt->size(),
		iterations);

	SecureZeroMemory(&newPass2, sizeof(newPass2));

	kdfHash.ProtectMemory(true);
	kdfSalt.ProtectMemory(true);

	winreg::RegKey policySettings(
		HKEY_LOCAL_MACHINE,
		"SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers",
		KEY_WRITE);

	policySettings.SetMultiStringValue("ExecutableTypes", executableTypes);

	passwordReset = true;

	cout << "done" << '\n';
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

void DataFileManager::ListRules() const
{
	const char removed = static_cast<char>(SecOption::REMOVED) + '0';
	const char whiteList = static_cast<char>(SecOption::WHITELIST) + '0';
	const char blackList = static_cast<char>(SecOption::BLACKLIST) + '0';

	auto sortedRules = userRuleInfo;
	sort(sortedRules.begin(), sortedRules.end(), 
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

	if (!sortedRules.empty())
	{
		cout << '\n';
		unsigned index = 0;

		if (sortedRules[0][0] == whiteList)
		{
			cout << "Allowed rules:\n";
			for (index; index < sortedRules.size(); index++)
			{
				if (sortedRules[index][SEC_OPTION] == whiteList)
					cout << sortedRules[index].substr(RULE_PATH_POS,
						sortedRules[index].length()) << '\n';

				else if (sortedRules[index][SEC_OPTION] == removed)
					cout << "Except: " << sortedRules[index].substr(RULE_PATH_POS,
						sortedRules[index].length()) << '\n';

				else
					break;
			}

			cout << '\n';
		}

		if (sortedRules[0][0] == blackList)
		{
			cout << "Denied rules:\n";
			for (index; index < sortedRules.size(); index++)
			{
				if (sortedRules[index][SEC_OPTION] == blackList)
					cout << sortedRules[index].substr(RULE_PATH_POS,
						sortedRules[index].length()) << '\n';

				else if (sortedRules[index][SEC_OPTION] == removed)
					cout << "Except: " << sortedRules[index].substr(RULE_PATH_POS,
						sortedRules[index].length()) << '\n';

				else
					break;
			}
		}
	}

	else
		cout << "No rules have been created\n";
}