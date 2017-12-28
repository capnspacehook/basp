#include "AppSecPolicy.hpp"
#include "DataFileManger.hpp"
#include "ProtectedPtr.hpp"
#include "WinReg.hpp"
#include "Windows.h"

#include "Crypto++\pwdbased.h"
#include "Crypto++\filters.h"
#include "Crypto++\osrng.h"
#include "Crypto++\files.h"
#include "Crypto++\sha.h"
#include "Crypto++\aes.h"
#include "Crypto++\gcm.h"

#include <filesystem>
#include <algorithm>
#include <exception>
#include <iostream>
#include <sstream>
#include <utility>
#include <vector>
#include <thread>
#include <string>

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
		if (adf.GetLastResult() != true)
		{
			goodOpen = false;
			cerr << "File modified!" << endl;
		}

	if (goodOpen)
	{
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
					RULE_PATH_POS, temp.find_last_of("|") - 4));

				getline(iss, temp);
			}

			ruleInfo.emplace_back(temp + "\n");
			rulePaths.emplace_back(temp.substr(
				RULE_PATH_POS, temp.find_last_of("|") - 4));

			while (getline(iss, temp))
			{
				ruleInfo.emplace_back(temp + "\n");
				rulePaths.emplace_back(temp.substr(
					RULE_PATH_POS, temp.find_last_of("|") - 4));
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
		string policySettings = "";
		RegKey policyKey(
			HKEY_LOCAL_MACHINE,
			"SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers",
			KEY_READ);
		
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
		cout << e.what() << endl;
	}
	catch (const exception &e)
	{
		cout << e.what() << endl;
	}
}

RuleFindResult DataFileManager::FindRule(SecOption option, RuleType type,
	const string &path, string &guid) const
{
	SecOption findOp = option;
	RuleType findType = type;
	RuleFindResult result = RuleFindResult::NO_MATCH;

	if (rulePaths.size() == 0)
		return result;
	
	auto iterator = lower_bound(rulePaths.begin(), rulePaths.end(), path);
	
	if (iterator != rulePaths.end() && !(path < *iterator))
	{
		string foundRule = ruleInfo[distance(rulePaths.begin(), iterator)];

		option = static_cast<SecOption>(
			(int)(foundRule.at(SEC_OPTION_POS) - '0'));

		type = static_cast<RuleType>(
			(int)(foundRule.at(RULE_TYPE_POS) - '0'));

		guid = foundRule.substr(foundRule.find_last_of("|") + 1,
			foundRule.length());
		guid.pop_back();

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
	const string &path, size_t &index) const
{
	SecOption findOp = option;
	RuleType findType = type;
	RuleFindResult result = RuleFindResult::NO_MATCH;

	if (userRulePaths.size() == 0)
		return result;

	auto iterator = lower_bound(userRulePaths.begin(), userRulePaths.end(), path);

	if (iterator != userRulePaths.end() && !(path < *iterator))
	{
		string foundRule = ruleInfo[distance(userRulePaths.begin(), iterator)];

		option = static_cast<SecOption>(
			(int)(foundRule.at(SEC_OPTION_POS) - '0'));

		type = static_cast<RuleType>(
			(int)(foundRule.at(RULE_TYPE_POS) - '0'));

		index = distance(userRulePaths.begin(), iterator);

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

void DataFileManager::UpdateUserRules(const vector<UserRule> &ruleNames, bool rulesRemoved)
{
	SecOption option;
	RuleType type;
	string location;
	size_t index;

	for (const auto& rule : ruleNames)
	{
		option = static_cast<SecOption>(get<SEC_OPTION>(rule));
		type = static_cast<RuleType>(get<RULE_TYPE>(rule));
		location = get<FILE_LOCATION>(rule);

		RuleFindResult result = FindUserRule(option, type, location, index);

		if (result == RuleFindResult::NO_MATCH && !rulesRemoved)
		{
			userRuleInfo.emplace_back(to_string(static_cast<int>(option))
				+ '|' + to_string(static_cast<int>(type))
				+ '|' + location);
		}

		else if (result != RuleFindResult::NO_MATCH && rulesRemoved)
		{
			removedRules.emplace_back(userRulePaths[index]);
			userRuleInfo.erase(userRuleInfo.begin() + index);
		}

		else if (result == RuleFindResult::DIFF_SEC_OP)
			userRuleInfo[index][SEC_OPTION] = static_cast<char>(option) + '0';
	}
}

void DataFileManager::WriteToFile(const vector<RuleData>& ruleData, WriteType writeType)
{
	try
	{
		if (writeType == WriteType::REMOVED_RULES)
		{
			for (const auto& rule : removedRules)
			{
				const auto rulePathRange = equal_range(
					rulePaths.begin(), rulePaths.end(), rule,
					[&rule](const string &lhs, const string &rhs)
					{
						bool ret = false;
						if (rhs == rule)
							ret = lhs.compare(0, rule.length(), rule) < 0;

						if (lhs == rule)
							ret = rhs.compare(0, rule.length(), rule) > 0;

						return ret;
					});
				
				const auto ruleInfoRange = make_pair(
					ruleInfo.begin() + distance(rulePathRange.second, rulePaths.end()),
					ruleInfo.begin() + distance(rulePathRange.first, rulePaths.end()));

				rulePaths.erase(rulePathRange.first, rulePathRange.second);
				ruleInfo.erase(ruleInfoRange.first, ruleInfoRange.second);
			}
		}

		else
		{
			int option;
			int type;
			string location;
			string guid;

			for (const auto& rule : ruleData)
			{
				option = static_cast<int>(get<SEC_OPTION>(rule));
				type = static_cast<int>(get<RULE_TYPE>(rule));
				location = get<FILE_LOCATION>(rule);
				guid = *get<RULE_GUID>(rule);

				if (writeType == WriteType::CREATED_RULES)
				{
					rulesAdded = true;

					rulePaths.emplace_back(location);
					ruleInfo.emplace_back(to_string(option) + '|' + to_string(type)
						+ '|' + location + '|' + guid + '\n');
				}

				else if (writeType == WriteType::SWITCHED_RULES)
				{
					if (rulesAdded)
					{
						sort(ruleInfo.begin(), ruleInfo.end(),
							[](const string &str1, const string &str2)
						{
							return str1.substr(RULE_PATH_POS,
								str1.find_last_of("|") - 4)
								< str2.substr(RULE_PATH_POS,
									str2.find_last_of("|") - 4);
						});

						rulePaths.clear();
						for (const auto& rule : ruleInfo)
						{
							rulePaths.emplace_back(rule.substr(RULE_PATH_POS,
								rule.find_last_of("|") - 4));
						}

						rulesAdded = false;
						rulesNotSorted = false;
					}

					auto iterator = lower_bound(
						rulePaths.begin(), rulePaths.end(), location);

					size_t index = distance(rulePaths.begin(), iterator);

					ruleInfo[index][SEC_OPTION] = static_cast<char>(option) + '0';
				}
			}
		}

		ReorganizePolicyData();
	}
	catch (const exception &e)
	{
		cerr << e.what() << endl;
	}
}

void DataFileManager::ReorganizePolicyData()
{
	if (rulesNotSorted)
	{
		sort(userRuleInfo.begin(), userRuleInfo.end());

		sort(ruleInfo.begin(), ruleInfo.end(),
			[](const string &str1, const string &str2)
			{
				return str1.substr(RULE_PATH_POS,
					str1.find_last_of("|") - 4)
					< str2.substr(RULE_PATH_POS,
					str2.find_last_of("|") - 4);
			});
	}

	policyData->clear();

	for (const auto& line : userRuleInfo)
		*policyData += line + '*' + '\n';

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

	cout << endl;
}

void DataFileManager::CheckPassword(string& guessPwd)
{
	bool validPwd;
	bool cmdPwd = true;

	if (guessPwd.size() == 0)
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

	cout << "done" << endl;
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
	auto sortedRules = userRuleInfo;
	sort(sortedRules.begin(), sortedRules.end(), 
		[](const string &str1, const string &str2)
	{
		if (str1[SEC_OPTION] != str2[SEC_OPTION])
			return str1[SEC_OPTION] > str2[SEC_OPTION];

		fs::path path1(str1.substr(RULE_PATH_POS,
			str1.find_last_of("|") - 4));

		fs::path path2(str2.substr(RULE_PATH_POS,
			str2.find_last_of("|") - 4));

		if (path1.parent_path() != path2.parent_path())
			return path1.parent_path() < path2.parent_path();

		else 
			return path1.filename() < path2.filename();
	});

	char whiteList = static_cast<char>(SecOption::WHITELIST) + '0';
	char blackList = static_cast<char>(SecOption::BLACKLIST) + '0';

	if (sortedRules.size() > 0)
	{
		unsigned index = 0;

		if (sortedRules[0][0] == whiteList)
		{
			cout << "Allowed rules:\n";
			for (index; index < sortedRules.size(); index++)
			{
				if (sortedRules[index][SEC_OPTION] == whiteList)
				{
					cout << sortedRules[index].substr(RULE_PATH_POS,
						sortedRules[index].find_last_of("|") - 4)
						<< "\n";
				}
				else
					break;
			}

			cout << endl;
		}

		if (sortedRules[0][0] == blackList)
		{
			cout << "Denied rules:\n";
			for (index; index < sortedRules.size(); index++)
			{
				if (sortedRules[index][SEC_OPTION] == blackList)
				{
					cout << sortedRules[index].substr(RULE_PATH_POS,
						sortedRules[index].find_last_of("|") - 4)
						<< "\n";
				}
				else
					break;
			}
		}
	}

	else
		cout << "No rules have been created\n";
}