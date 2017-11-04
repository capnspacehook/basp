#include "AppSecPolicy.hpp"
#include "SecPolicy.hpp"
#include "HashRule.hpp"
#include "WinReg.hpp"

#include "Windows.h"
#include <strsafe.h>

#include <filesystem>
#include <system_error>
#include <algorithm>
#include <iostream>
#include <cstdlib>
#include <thread>
#include <string>
#include <cctype>
#include <vector>

#pragma comment(lib, "User32.lib")

using namespace std;
using namespace AppSecPolicy;
namespace fs = std::experimental::filesystem;

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
			KEY_READ);

		executableTypes = policyOptions.GetMultiStringValue("ExecutableTypes");

		policyOptions.Close();
	}
	catch (const RegException &e)
	{
		cout << e.what() << endl;
		exit;
	}
	catch (...)
	{
		cout << "Unknown exception" << endl;
		exit;
	}
}

//detirmine whether file passed to constructor is a 
//regular file or directory and process respectively
void SecPolicy::EnumAttributes(const string &fileName) noexcept
{
	try
	{
		auto err = error_code();
		auto initialFile = fs::path(fileName);

		if (fs::exists(initialFile, err))
		{
			if (fs::is_directory(initialFile, err))
				EnumDirContents(initialFile, err);

			else
				CheckValidType(initialFile);
		}
		else
			cout << initialFile.string() << " doesn't exist!" << endl;
	}
	catch (const error_code &e)
	{
		cout << e.message() << endl;
		exit;
	}
	catch (...)
	{
		cout << "Unknown exception" << endl;
		exit;
	}
}

//recursively go through directory 
void SecPolicy::EnumDirContents(const fs::path& dir, const error_code& err) noexcept
{
	try
	{
		for (const auto &currFile : fs::directory_iterator(dir))
		{
			if (fs::exists(currFile))
			{
				if (fs::is_directory(currFile))
					EnumDirContents(currFile.path(), err);
				else
					CheckValidType(currFile);
			}
			else
				continue;
		}
	}
	catch (const error_code &e)
	{
		cout << e.message() << endl;
	}
	catch (...)
	{
		cout << "Unknown exception" << endl;
	}
}

//checks whether file is a valid type as detirmined by the list 
//in the member variable executableTypes
void SecPolicy::CheckValidType(const fs::path &file) noexcept
{
	try
	{
		if (file.has_extension())
		{
			for (const auto &exeType : executableTypes)
				if (FindInStrIC(file.extension().string(), exeType))
					threads.emplace_back(
						&HashRule::CreateNewHashRule,
						HashRule(),
						file.string(),
						secOption);
		}
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

//returns true if extension and exeType are the same; case insensitive
inline bool SecPolicy::FindInStrIC(string extension, string exeType) const noexcept
{
	extension = extension.substr(1, extension.length());

	for (int i = 0; i < extension.length(); i++)
		extension[i] = toupper(extension[i]);

	return extension == exeType;
}