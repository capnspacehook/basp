#include "AppSecPolicy.hpp"
#include "SecPolicy.hpp"
#include "HashRule.hpp"
#include "WinReg.hpp"
#include "Windows.h"

#include <filesystem>
#include <exception>
#include <algorithm>
#include <iostream>
#include <fstream>
#include <utility>
#include <chrono>
#include <thread>
#include <string>
#include <vector>

using namespace std;
using namespace AppSecPolicy;
namespace fs = std::experimental::filesystem;

//create hash rules recursively in 'path'
void SecPolicy::CreatePolicy(const string &path, const SecOptions &op, 
	RuleType rType)
{
	secOption = op;
	ruleType = rType;
	EnumAttributes(path);
}

//overload that creates hash rules for each of the files in the vector 'paths'
void SecPolicy::CreatePolicy(const vector<string> &paths, const SecOptions &op,
	RuleType rType)
{
	secOption = op;
	ruleType = rType;

	fs::path pathName;
	for (const auto &path : paths)
	{
		pathName.assign(path);
		EnumAttributes(path);
	}
}

//create a whitelisting rule, execute the file passed in, and delete the rule
void SecPolicy::TempRun(const string &path) 
{
	try
	{
		tempRuleCreation = true;
		fs::path file = fs::path(path);

		long long size = fs::file_size(file);
		if (size > 0)
		{
			//create temporary hash rule
			string subKey;
			HashRule tempRule;
			tempRule.CreateNewHashRule(path, SecOptions::WHITELIST, size, &subKey);
			ApplyChanges(false);

			ruleCount++;
			cout << "Created temporary allow rule for " << file.string()
				<< ". Executing file now...\n\n";

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

			tempRule.RemoveRule(&subKey, SecOptions::WHITELIST);
			cout << "Temporary rule deleted" << endl;
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
	catch (...)
	{
		cout << "Unknown exception" << endl;
	}
}

//overload that temporaily whitelists 'dir', and executes 'file'
void SecPolicy::TempRun(const string &dir, const string &file) 
{
	try
	{
		auto tempDir = fs::path(dir);
		auto exeFile = fs::path(file);

		tempRuleCreation = true;
		CreatePolicy(dir, SecOptions::WHITELIST);
		
		//wait for hash creation threads to finish before trying 
		//to delete the rules they may or may not be finished
		for (auto &t : threads)
			t.join();

		ApplyChanges(false);

		cout << "\nCreated temporary allow rules in " << tempDir.string()
			<< ". Executing " << exeFile.string() << " now...\n\n";

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

		//delete temporary rules in parallel
		threads.clear();
		for (const auto &tempRuleID : rulesInfo)
			threads.emplace_back(
				&HashRule::RemoveRule,
				HashRule(),
				get<RULE_GUID>(tempRuleID),
				SecOptions::WHITELIST);

		//clear temp rules
		rulesInfo.clear();
	}
	catch (const fs::filesystem_error &e)
	{
		cerr << e.what() << endl;
	}
	catch (const exception &e)
	{
		cerr << e.what() << endl;
	}
	catch (...)
	{
		cerr << "Unknown exception" << endl;
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

bool SecPolicy::SetPrivileges(const string& privName, const bool& enablePriv)
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
void SecPolicy::CheckGlobalSettings() const
{
	using namespace winreg;
	try 
	{
		RegKey policySettings(
			HKEY_LOCAL_MACHINE,
			"SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers",
			KEY_READ | KEY_WRITE);

		vector<pair<string, DWORD>> keys = policySettings.EnumValues();

		if (keys.size() < 5)
		{
			policySettings.SetDwordValue("AuthenticodeEnabled", 0);
			policySettings.SetDwordValue("DefaultLevel", 262144);
			policySettings.SetMultiStringValue("ExecutableTypes", executableTypes);
			policySettings.SetDwordValue("PolicyScope", 0);
			policySettings.SetDwordValue("TransparentEnabled", 1);
		}

		//if what's in the registry differs from what we have, update the registry
		if (executableTypes != policySettings.GetMultiStringValue("ExecutableTypes"))
			policySettings.SetMultiStringValue("ExecutableTypes", executableTypes);
	}
	catch (const RegException &e)
	{
		cout << e.what() << endl;
	}
	catch (const exception &e)
	{
		cout << e.what() << endl;
	}
	catch (...)
	{
		cout << "Unknown exception" << endl;
	}
}

//detirmine whether file passed to constructor is a 
//regular file or directory and process respectively
void SecPolicy::EnumAttributes(const string &fileName) 
{
	try
	{
		
		auto initialFile = fs::path(fileName);

		string action;
		long long fileSize;
		((bool)secOption) ? action = "whitelisting" : action = "blacklisting";

		if (fs::is_directory(initialFile))
		{
			if (tempRuleCreation)
			{
				((bool)secOption) ? action = "whitelisting" 
					: action = "blacklisting";

				cout << "Temporaily " << action << " files in "
					<< initialFile.string()  << "..." << endl;
			}
			else
			{
				((bool)secOption) ? action = "Whitelisting"
					: action = "Blacklisting";

				cout << action << " files in "
					<< initialFile.string() << "..." << endl;
			}
			
			EnumDirContents(initialFile, fileSize);
		}
		else
		{
			fileSize = fs::file_size(initialFile);
			if (fileSize && fs::is_regular_file(initialFile))
			{
				cout << action << " "
					<< initialFile.string() << endl;
				CheckValidType(initialFile, fileSize);
			}
			else
			{
				cout << "Can't create hash rule for " <<
					initialFile.string() << endl;
				exit(-1);
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
	catch (...)
	{
		cout << "Unknown exception" << endl;
	}
}

//recursively go through directory 
void SecPolicy::EnumDirContents(const fs::path& dir, long long &fileSize) 
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
					fileSize = fs::file_size(currFile);
					if (fileSize && fs::is_regular_file(currFile))
						CheckValidType(currFile, fileSize);
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
	catch (...)
	{
		cout << "Unknown exception" << endl;
	}
}

//checks whether file is a valid type as detirmined by the list 
//in the member variable executableTypes and if it is, start creating
//a new hash rule for the file in a new thread
void SecPolicy::CheckValidType(const fs::path &file, const long long &fileSize) 
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
			if (binary_search(
				executableTypes.cbegin(), 
				executableTypes.cend(), 
				extension))
			{
				ruleCount++;
				
				rulesInfo.emplace_back(make_tuple(secOption, ruleType,
					file.string(), new string));
				threads.emplace_back(
					&HashRule::CreateNewHashRule,
					HashRule(),
					file.string(),
					secOption,
					fileSize,
					get<RULE_GUID>(rulesInfo.back()));
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
	catch (...)
	{
		cout << "Unknown exception" << endl;
	}
}

void SecPolicy::WriteToPolicyFile()
{

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

	if (tempRuleCreation)
	{
		if (mins > 0)
		{
			cout << "Created and removed " << ruleCount
				<< " temporary hash rules in " << mins << " mins, "
				<< secs << " secs " << endl;
		}
		else
		{
			cout << "Created and removed " << ruleCount
				<< " temporary hash rules in "
				<< secs << " secs " << endl;
		}
	}
	else
	{
		if (mins > 0)
		{
			cout << "Created " << ruleCount << " hash rules in "
				<< mins << " mins, " << secs << " secs" << endl;
		}
		else
		{
			cout << "Created " << ruleCount << " hash rules in "
				<< secs << " secs" << endl;
		}
	}
} 

//make sure Windows applies policy changes
void SecPolicy::ApplyChanges(bool updateSettings)
{
	//Windows randomly applies the rules that are written to the registry,
	//so to persuade Windows to apply the rule changes we have to change a 
	//global policy setting. I add a random executeable type and then remove it
	//so that it doesn't really affect anything. Changing any other of the global
	//rules even for a split second, is a security risk
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
		if(updateSettings)
			dataFileMan.WriteToFile(rulesInfo);

		cout << "done" << endl;
	}
	catch (const RegException &e)
	{
		cout << e.what() << endl;
	}
	catch (const exception &e)
	{
		cout << e.what() << endl;
	}
	catch (...)
	{
		cout << "Unknown exception" << endl;
	}
}