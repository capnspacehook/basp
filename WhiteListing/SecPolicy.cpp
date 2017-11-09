#include "AppSecPolicy.hpp"
#include "SecPolicy.hpp"
#include "HashRule.hpp"
#include "WinReg.hpp"

#include <filesystem>
#include <exception>
#include <algorithm>
#include <iostream>
#include <thread>
#include <string>
#include <cctype>
#include <vector>

using namespace std;
using namespace AppSecPolicy;
namespace fs = std::experimental::filesystem;

//create hash rules recursively in 'path'
void SecPolicy::CreatePolicy(const string &path, const SecOptions &op) noexcept
{
	secOption = op;
	EnumExeTypes();
	EnumAttributes(path);
}

//overload that creates hash rules for each of the files in the vector 'paths'
void SecPolicy::CreatePolicy(const vector<string> &paths, const SecOptions &op) noexcept
{
	secOption = op;
	EnumExeTypes();

	fs::path pathName;
	for (const auto &path : paths)
	{
		pathName.assign(path);
		EnumAttributes(path);
		cout << "Finished creating hash rules for "
			<< pathName << endl << endl;
	}
}

//create a whitelisting rule, execute the file passed in, and delete the rule
void SecPolicy::TempRun(const string &path) noexcept
{
	try
	{
		tempRuleCreation = true;
		auto file = fs::path(path);

		long long size = fs::file_size(file);
		if (size > 0)
		{
			//create temporary hash rule
			string subKey;
			HashRule tempRule;
			tempRule.CreateTempHashRule(path, SecOptions::WHITELIST, size, &subKey);

			ruleCount++;
			cout << "\nCreated temporary allow rule for " << file.string()
				<< ". Executing file now...\n\n";

			// start the program up
			STARTUPINFO si;
			PROCESS_INFORMATION pi;
			SecureZeroMemory(&si, sizeof(si));
			si.cb = sizeof(si);
			SecureZeroMemory(&pi, sizeof(pi));

			CreateProcess(path.c_str(),
				NULL,
				NULL,
				NULL,
				FALSE,
				0,
				NULL,
				NULL,
				&si,
				&pi
			);
				
			Sleep(1000);
			// Close process and thread handles. 
			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);

			tempRule.DeleteTempRule(&subKey, SecOptions::WHITELIST);
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
void SecPolicy::TempRun(const string &dir, const string &file) noexcept
{
	try
	{
		auto tempDir = fs::path(dir);
		auto exeFile = fs::path(file);

		tempRuleCreation = true;
		CreatePolicy(dir, SecOptions::WHITELIST);
		
		//wait for threads to finish before trying to delete the rules 
		//they may or may not be done creating
		for (auto &t : threads)
			t.join();

		cout << "\nCreated temporary allow rules in " << tempDir.string()
			<< ". Executing " << exeFile.string() << " now...\n\n";

		// start the program up
		STARTUPINFO si;
		PROCESS_INFORMATION pi;
		SecureZeroMemory(&si, sizeof(si));
		si.cb = sizeof(si);
		SecureZeroMemory(&pi, sizeof(pi));

		CreateProcess(file.c_str(),
			NULL,
			NULL,
			NULL,
			FALSE,
			0,
			NULL,
			NULL,
			&si,
			&pi
		);

		Sleep(1000);
		// Close process and thread handles. 
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);

		//delete temporary rules in parallel
		threads.clear();
		for (const auto &tempRuleID : GUIDs)
			threads.emplace_back(
				&HashRule::DeleteTempRule,
				HashRule(),
				tempRuleID,
				SecOptions::WHITELIST);
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

//gets the types specified in the registry that Windows
//will treat as executable files for software policy purposes
//if a file extension isn't on the list returned a file of 
//it's type won't get blacklisted/whitelisted
void SecPolicy::EnumExeTypes() noexcept
{
	using namespace winreg;
	try 
	{
		RegKey policyOptions(
			HKEY_LOCAL_MACHINE,
			"SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers",
			KEY_READ | KEY_WRITE);

		//if what's in the registry differs from what we have, update the registry
		if (executableTypes != policyOptions.GetMultiStringValue("ExecutableTypes"))
			policyOptions.SetMultiStringValue("ExecutableTypes", executableTypes);
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
void SecPolicy::EnumAttributes(const string &fileName) noexcept
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
					<< initialFile.string() << endl;
			}
			else
			{
				((bool)secOption) ? action = "Whitelisting"
					: action = "Blacklisting";

				cout << action << " files in "
					<< initialFile.string() << endl;
			}
			
			EnumDirContents(initialFile, fileSize);
		}
		else
		{
			if (tempRuleCreation)
			{
				cout << "If you wish to temporarily run a single file, please "
					<< "specify only one file and omit the -e option" << endl;
				exit(-1);
			}
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
void SecPolicy::EnumDirContents(const fs::path& dir, long long &fileSize) noexcept
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
void SecPolicy::CheckValidType(const fs::path &file, const long long &fileSize) noexcept
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
			for (int i = 0; i < executableTypes.size(); i++)
			{
				if (extension == executableTypes[i])
				{
					/*if (i > 0)
						swap(executableTypes[i - 1], executableTypes[i]);*/

					ruleCount++;
					if (tempRuleCreation)
					{
						GUIDs.emplace_back(new string);
						threads.emplace_back(
							&HashRule::CreateTempHashRule,
							HashRule(),
							file.string(),
							secOption,
							fileSize,
							GUIDs.back());
					}
					else
						threads.emplace_back(
							&HashRule::CreateNewHashRule,
							HashRule(),
							file.string(),
							secOption,
							fileSize);

					break;
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
	catch (...)
	{
		cout << "Unknown exception" << endl;
	}
}