#include "AppSecPolicy.hpp"
#include "SecPolicy.hpp"
#include "HashRule.hpp"
#include "WinReg.hpp"
#include "Windows.h"

#include <filesystem>
#include <exception>
#include <algorithm>
#include <iostream>
#include <sstream>
#include <memory>
#include <chrono>
#include <thread>
#include <string>
#include <vector>

using namespace std;
using namespace AppSecPolicy;
namespace fs = std::experimental::filesystem;

//create hash rules recursively in 'path'
void SecPolicy::CreatePolicy(const string &path, const SecOption &op, 
	RuleType rType)
{
	dataFileMan.VerifyPassword(passwordGuess);
	CheckGlobalSettings();
	StartTimer();

	secOption = op;
	ruleType = rType;

	enteredRules.emplace_back(
		secOption, ruleType, path);
	EnumAttributes(path);
}

//overload that creates hash rules for each of the files in the vector 'paths'
void SecPolicy::CreatePolicy(const vector<string> &paths, const SecOption &op,
	RuleType rType)
{
	dataFileMan.VerifyPassword(passwordGuess);
	CheckGlobalSettings();
	StartTimer();

	secOption = op;
	ruleType = rType;

	for (const auto &path : paths)
	{
		enteredRules.emplace_back(
			secOption, ruleType, path);
		EnumAttributes(path);
	}
}

//create a whitelisting rule, execute the file passed in, and delete the rule
void SecPolicy::TempRun(const string &path) 
{
	try
	{
		dataFileMan.VerifyPassword(passwordGuess);
		CheckGlobalSettings();
		StartTimer();

		tempRuleCreation = true;
		fs::path file = fs::path(path);
		file.make_preferred();

		uintmax_t size = fs::file_size(file);
		if (size > 0)
		{
			//create temporary hash rule
			shared_ptr<string> subKey = make_shared<string>("");
			HashRule tempRule;

			string guid;
			RuleFindResult result = dataFileMan.FindRule(
				SecOption::BLACKLIST, ruleType, file.string(), guid);

			if (result == RuleFindResult::NO_MATCH)
			{
				createdRules++;
				tempRule.CreateNewHashRule(path, SecOption::WHITELIST, size,
					subKey);
				ApplyChanges(false);
			}

			else if (result == RuleFindResult::EXACT_MATCH)
			{
				switchedRules++;
				tempRule.SwitchRule(guid, SecOption::WHITELIST);
				ApplyChanges(false);
			}

			if (result == RuleFindResult::DIFF_SEC_OP)
			{
				skippedRules++;
				cout << file.string() << " is already allowed.";
			}

			else
				cout << "Temporarily allowed " << file.string();

			cout << ". Executing file now...\n\n";

			// start the program up
			STARTUPINFO si;
			PROCESS_INFORMATION pi;

			SecureZeroMemory(&si, sizeof(si));
			SecureZeroMemory(&pi, sizeof(pi));

			si.cb = sizeof(si);
			bool procCreated = CreateProcess(
				NULL,
				(char*) file.string().c_str(),
				NULL,
				NULL,
				FALSE,
				NULL,
				NULL,
				(char*) file.parent_path().string().c_str(),
				&si,
				&pi);

			if (!procCreated)
			{
				cerr << "CreateProcess error: " << GetLastError() << endl;
			}
				
			Sleep(1000);
			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);

			if (result == RuleFindResult::NO_MATCH)
			{
				removedRules++;
				tempRule.RemoveRule(*subKey, SecOption::WHITELIST);
				cout << "Temporary rule deleted\n";
			}

			else if (result == RuleFindResult::EXACT_MATCH)
			{
				switchedRules++;
				tempRule.SwitchRule(guid, SecOption::BLACKLIST);
				cout << "Rule switched back to deny mode.\n";
			}
		}
		else
		{
			cout << "Can't create hash rule for " <<
				file.string() << endl;
			exit(-1);
		}
	}
	catch (const fs::filesystem_error &e)
	{
		cout << e.what() << endl;
	}
	catch (const exception &e)
	{
		cout << e.what() << endl;
	}
}

//overload that temporaily whitelists 'dir', and executes 'file'
void SecPolicy::TempRun(const string &dir, const string &file) 
{
	try
	{
		dataFileMan.VerifyPassword(passwordGuess);
		CheckGlobalSettings();
		StartTimer();

		auto tempDir = fs::path(dir);
		auto exeFile = fs::path(file);

		tempDir.make_preferred();
		exeFile.make_preferred();

		tempRuleCreation = true;
		CreatePolicy(dir, SecOption::WHITELIST);
		
		//wait for hash creation threads to finish before trying 
		//to delete the rules they may or may not be finished
		for (auto &t : threads)
			t.join();

		ApplyChanges(false);

		cout << ". Executing " << exeFile.string() << " now...\n\n";

		// start the program up
		STARTUPINFO si;
		PROCESS_INFORMATION pi;

		SecureZeroMemory(&si, sizeof(si));
		SecureZeroMemory(&pi, sizeof(pi));

		si.cb = sizeof(si);
		bool procCreated = CreateProcess(
			NULL,
			(char*) exeFile.string().c_str(),
			NULL,
			NULL,
			FALSE,
			NULL,
			NULL,
			(char*) exeFile.parent_path().string().c_str(),
			&si,
			&pi);

		if (!procCreated)
		{
			cerr << "CreateProcess error: " << GetLastError() << endl;
			return;
		}

		Sleep(1000);
		// Close process and thread handles. 
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);

		cout << "Reverting temporary changes...";

		//delete temporary rules in parallel
		threads.clear();
		for (const auto &tempRuleID : createdRulesData)
		{
			removedRules++;
			threads.emplace_back(
				&HashRule::RemoveRule,
				HashRule(),
				*get<RULE_GUID>(tempRuleID),
				SecOption::WHITELIST);
		}

		for (auto &t : threads)
			t.join();

		threads.clear();
		for (const auto &tempRuleID : switchedRulesData)
		{
			switchedRules++;
			threads.emplace_back(
				&HashRule::SwitchRule,
				HashRule(),
				*get<RULE_GUID>(tempRuleID),
				SecOption::BLACKLIST);
		}

		cout << "done" << endl;

		//clear temp rules
		createdRulesData.clear();
		switchedRulesData.clear();
	}
	catch (const fs::filesystem_error &e)
	{
		cerr << e.what() << endl;
	}
	catch (const exception &e)
	{
		cerr << e.what() << endl;
	}
}

//delete rules from registry
void SecPolicy::RemoveRules(const string &path)
{
	dataFileMan.VerifyPassword(passwordGuess);
	CheckGlobalSettings();
	StartTimer();

	ruleRemoval = true;
	enteredRules.emplace_back(
		secOption, ruleType, path);
	EnumAttributes(path);
}

void SecPolicy::RemoveRules(const vector<string> &paths)
{
	dataFileMan.VerifyPassword(passwordGuess);
	CheckGlobalSettings();
	StartTimer();

	ruleRemoval = true;
	for (const auto &path : paths)
	{
		enteredRules.emplace_back(
			secOption, ruleType, path);
		EnumAttributes(path);
	}
}

void SecPolicy::EnumLoadedDLLs(const string &exeFile)
{
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	DEBUG_EVENT debugEvent;
	fs::path exePath(exeFile);

	SecureZeroMemory(&si, sizeof(si));
	SecureZeroMemory(&pi, sizeof(pi));

	// Create target process
	si.cb = sizeof(si);
	bool procCreated = CreateProcess(
		NULL,
		(char*) exeFile.c_str(),
		NULL,
		NULL,
		TRUE,
		DEBUG_PROCESS,
		NULL,
		(char*) exePath.parent_path().string().c_str(),
		&si,
		&pi);

	if (!procCreated)
	{
		cerr << "CreateProcess error: " << GetLastError() << endl;
		return;
	}

	DebugSetProcessKillOnExit(TRUE);
	DebugActiveProcess(pi.dwProcessId);

	char dllPath[MAX_PATH];
	while (true)
	{
		if (!WaitForDebugEvent(&debugEvent, dllWaitSecs * 1000))
			break;

		if (debugEvent.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT)
		{
			GetFinalPathNameByHandle(
				debugEvent.u.LoadDll.hFile, dllPath, MAX_PATH, FILE_NAME_OPENED);

			cout << "New DLL found: " << dllPath << endl;

			CloseHandle(debugEvent.u.LoadDll.hFile);
		}
		else if (debugEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
			if (debugEvent.u.Exception.ExceptionRecord.ExceptionFlags != 0)
			{
				cerr << "Fatal exception thrown" << endl;
				break;
			}

		ContinueDebugEvent(debugEvent.dwProcessId,
			debugEvent.dwThreadId,
			DBG_CONTINUE);
	}

	DebugActiveProcessStop(pi.dwProcessId);
	TerminateProcess(pi.hProcess, 0);

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
}

void SecPolicy::ListRules()
{
	dataFileMan.VerifyPassword(passwordGuess);
	CheckGlobalSettings();
	StartTimer();

	dataFileMan.ListRules();
}

bool SecPolicy::SetPrivileges(const string& privName, bool enablePriv)
{
	HANDLE tokenH;
	HANDLE localProc = GetCurrentProcess();
	if (!OpenProcessToken(localProc, TOKEN_ADJUST_PRIVILEGES, &tokenH))
	{
		cerr << "OpenProcessToken error: " << GetLastError();
		return false;
	}

	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!LookupPrivilegeValue(
		NULL,            // lookup privilege on local system
		privName.c_str(),   // privilege to lookup 
		&luid))        // receives LUID of privilege
	{
		cerr << "LookupPrivilegeValue error: " << GetLastError() << endl;
		return false;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (enablePriv)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	// Enable the privilege or disable all privileges.

	if (!AdjustTokenPrivileges(
		tokenH,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		cerr << "AdjustTokenPrivileges error: " << GetLastError() << endl;
		return false;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

	{
		cerr << "The token does not have the specified privilege." << endl;
		return false;
	}

	return true;
}

//makes sure all the nessesary settings are in place to apply a SRP policy,
//if a computer has never had policy applied before it will be missing
//some of these settings. Also check if values in registry are what they should be
void SecPolicy::CheckGlobalSettings()
{
	using namespace winreg;
	try 
	{
		RegKey policySettings(
			HKEY_LOCAL_MACHINE,
			"SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers",
			KEY_READ | KEY_WRITE);

		string globalSettings = dataFileMan.GetGlobalSettings();
		string exetensions = globalSettings.substr(globalSettings.find_last_of('|') + 1,
			globalSettings.length());

		string type;
		istringstream iss(exetensions);

		while (getline(iss, type, ','))
			executableTypes.emplace_back(type);

		vector<pair<string, DWORD>> keys = policySettings.EnumValues();

		if (keys.size() < 5)
		{
			policySettings.SetDwordValue("AuthenticodeEnabled", 0);
			policySettings.SetDwordValue("DefaultLevel", 262144);
			policySettings.SetMultiStringValue("ExecutableTypes", executableTypes);
			policySettings.SetDwordValue("PolicyScope", 0);
			policySettings.SetDwordValue("TransparentEnabled", 1);
		}
		
		if (globalSettings != dataFileMan.GetCurrentPolicySettings())
		{
			cout << "Proceed with caution! Unauthorized changes have been made "
				<< "to the global policy settings.\n"
				<< "Correct settings were reapplied.\n\n";

			policySettings.SetDwordValue("AuthenticodeEnabled", 
				static_cast<int>(globalSettings[AUTHENTICODE_ENABLED] - '0'));

			int defaultLevel = static_cast<int>(globalSettings[DEFAULT_LEVEL] - '0');
			if (defaultLevel == 1)
				defaultLevel = 262144;

			policySettings.SetDwordValue("DefaultLevel", defaultLevel);

			policySettings.SetMultiStringValue("ExecutableTypes", executableTypes);

			policySettings.SetDwordValue("PolicyScope", 
				static_cast<int>(globalSettings[POLCIY_SCOPE] - '0'));

			policySettings.SetDwordValue("TransparentEnabled", 
				static_cast<int>(globalSettings[TRANSPARENT_ENABLED] - '0'));
		}
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

//detirmine whether file passed is a 
//regular file or directory and process respectively
void SecPolicy::EnumAttributes(const string &fileName) 
{
	try
	{
		fs::path initialFile(fileName);
		initialFile.make_preferred();

		string action;
		uintmax_t fileSize;

		if (fs::is_directory(initialFile))
		{
			if (tempRuleCreation)
			{
				cout << "Temporaily whitelisting files in "
					<< initialFile.string()  << "...";
			}

			else if (ruleRemoval)
			{
				cout << "Removing rules in " << initialFile.string()
					<< "...";
			}

			else
			{
				((bool)secOption) ? action = "Whitelisting" 
					: action = "Blacklisting";

				cout << action << " files in "
					<< initialFile.string() << "...";
			}
			
			EnumDirContents(initialFile, fileSize);
			cout << "done" << endl;
		}
		else
		{
			if (ruleRemoval)
			{
				cout << "Removing" << initialFile.string();
				DeleteRule(initialFile);
				cout << "done" << endl;
			}

			else
			{
				fileSize = fs::file_size(initialFile);
				if (fileSize && fs::is_regular_file(initialFile))
				{
					((bool)secOption) ? action = "Whitelisting"
						: action = "Blacklisting";

					cout << action << " "
						<< initialFile.string();

					CheckValidType(initialFile, fileSize);
					cout << "done" << endl;
				}

				else
				{
					cout << "Can't create hash rule for " <<
						initialFile.string() << endl;
					exit(-1);
				}
			}
		}
	}
	catch (const fs::filesystem_error &e)
	{
		cout << e.what() << endl;
	}
	catch (const exception &e)
	{
		cout << e.what() << endl;
	}
}

//recursively go through directory 
void SecPolicy::EnumDirContents(const fs::path& dir, uintmax_t &fileSize)
{
	try
	{
		for (const auto &currFile : fs::directory_iterator(dir))
		{
			if (fs::exists(currFile))
			{
				if (fs::is_directory(currFile))
					EnumDirContents(currFile.path(), fileSize);
				else
				{
					if (ruleRemoval)
						DeleteRule(currFile);

					else
					{
						fileSize = fs::file_size(currFile);
						if (fileSize && fs::is_regular_file(currFile))
							CheckValidType(currFile, fileSize);
					}
				}
			}
			else
				continue;
		}
	}
	catch (const fs::filesystem_error &e)
	{
		cout << e.what() << endl;
	}
	catch (const exception &e)
	{
		cout << e.what() << endl;
	}
}

//checks whether file is a valid type as detirmined by the list 
//in the member variable executableTypes and if it is, start creating
//a new hash rule for the file in a new thread
void SecPolicy::CheckValidType(const fs::path &file, const uintmax_t &fileSize)
{
	try
	{
		if (file.has_extension())
		{
			//convert file name to just the extension
			string extension = file.extension().string();
			extension = extension.substr(1, extension.length());
			
			transform(extension.begin(), extension.end(),
				extension.begin(), toupper);

			//check if the file is of one of the executable types 
			if (binary_search(executableTypes.cbegin(),
				executableTypes.cend(), extension))
			{
				string path;
				string guid;

				string temp = file.string();
				transform(temp.begin(), temp.end(),
					back_inserter(path), tolower);

				RuleFindResult result = dataFileMan.FindRule(
					secOption, ruleType, path, guid);

				if (result == RuleFindResult::NO_MATCH)
				{
					createdRules++;

					createdRulesData.emplace_back(make_tuple(secOption, ruleType,
						path, make_shared<string>(guid)));

					threads.emplace_back(
						&HashRule::CreateNewHashRule,
						HashRule(),
						path,
						secOption,
						fileSize,
						get<RULE_GUID>(createdRulesData.back()));
				}
				else if (result == RuleFindResult::DIFF_SEC_OP)
				{
					switchedRules++;

					switchedRulesData.emplace_back(make_tuple(secOption, ruleType,
						path, make_shared<string>(guid)));

					threads.emplace_back(
						&HashRule::SwitchRule,
						HashRule(),
						*get<RULE_GUID>(switchedRulesData.back()),
						secOption);
				}
				else if (result == RuleFindResult::EXACT_MATCH)
					skippedRules++;
			}
		}
	}
	catch (const fs::filesystem_error &e)
	{
		cout << e.what() << endl;
	}
	catch (const exception &e)
	{
		cout << e.what() << endl;
	}
}

void SecPolicy::DeleteRule(const fs::path &file)
{
	string path;
	string guid;
	string temp = file.string();
	transform(temp.begin(), temp.end(),
		back_inserter(path), tolower);

	SecOption ruleOp = SecOption::BLACKLIST;
	RuleFindResult result = dataFileMan.FindRule(
		ruleOp, RuleType::HASHRULE, path, guid);

	if (result != RuleFindResult::NO_MATCH)
	{
		if (result == RuleFindResult::DIFF_SEC_OP)
			ruleOp = SecOption::WHITELIST;

		removedRulesData.emplace_back(make_tuple(ruleOp, RuleType::HASHRULE,
			path, make_shared<string>(guid)));

		removedRules++;
		threads.emplace_back(
			&HashRule::RemoveRule,
			HashRule(),
			*get<RULE_GUID>(removedRulesData.back()),
			ruleOp);
	}

	else
		skippedRules++;

}

//print how many rules were created and runtime of rule creation
void SecPolicy::PrintStats() const
{
	common_type_t<chrono::nanoseconds,
		chrono::nanoseconds> diff =
		chrono::high_resolution_clock::now() - startTime;

	int secs;
	int mins = chrono::duration<double, milli>(diff).count() / 60000;

	if (mins > 0)
		secs = (int)(chrono::duration<double, milli>(diff).count() / 1000) % (mins * 60);
	else
		secs = chrono::duration<double, milli>(diff).count() / 1000;

	cout << "Created " << createdRules << " rules,\n"
		<< "Switched " << switchedRules << " rules,\n"
		<< "Skipped " << skippedRules << " rules, and\n"
		<< "Removed " << removedRules << " rules "
		<< "in ";

	if (mins > 0)
		cout << mins << " mins, " << secs << " secs" << endl;
	
	else
		cout << secs << " secs" << endl;
} 

//make sure Windows applies policy changes
void SecPolicy::ApplyChanges(bool updateSettings)
{
	//Windows randomly applies the rules that are written to the registry,
	//so to persuade Windows to apply the rule changes we have to change a 
	//global policy setting. A random executeable type is added and then removed 
	//so that it doesn't really affect anything. Changing any other of the global
	//rules even for a split second, is a security risk.
	using namespace winreg;
	try 
	{
		cout << endl << "Applying changes...";

		executableTypes.push_back("ABC");
		RegKey policySettings(
			HKEY_LOCAL_MACHINE,
			"SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers",
			KEY_READ | KEY_WRITE);

		policySettings.SetMultiStringValue("ExecutableTypes", executableTypes);
		Sleep(1000);

		executableTypes.pop_back();
		policySettings.SetMultiStringValue("ExecutableTypes", executableTypes);

		//write changes to settings file
		if (updateSettings && !tempRuleCreation)
		{
			dataFileMan.UpdateUserRules(enteredRules, ruleRemoval);

			if (createdRules)
				dataFileMan.WriteToFile(createdRulesData, WriteType::CREATED_RULES);

			if (switchedRules)
				dataFileMan.WriteToFile(switchedRulesData, WriteType::SWITCHED_RULES);

			if (removedRules)
				dataFileMan.WriteToFile(removedRulesData, WriteType::REMOVED_RULES);
		}

		cout << "done\n\n";
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