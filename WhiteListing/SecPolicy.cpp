#include "AppSecPolicy.hpp"
#include "SecPolicy.hpp"
#include "HashRule.hpp"
#include "WinReg.hpp"

#include <filesystem>
#include <system_error>
#include <algorithm>
#include <iostream>
#include <thread>
#include <string>
#include <cctype>
#include <vector>

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
			KEY_READ | KEY_WRITE);

		if (executableTypes != policyOptions.GetMultiStringValue("ExecutableTypes"))
			policyOptions.SetMultiStringValue("ExecutableTypes", executableTypes);
	}
	catch (const RegException &e)
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

		if (fs::exists(initialFile))
		{
			long long fileSize;
			if (fs::is_directory(initialFile))
			{
				cout << "Creating hash rules recursively on "
					<< initialFile.string() << endl;
				EnumDirContents(initialFile, fileSize);
			}
			else
			{
				fileSize = fs::file_size(initialFile);
				if (fileSize && fs::is_regular_file(initialFile))
				{
					cout << "Creating hash rule for "
						<< initialFile.string() << endl;
					CheckValidType(initialFile, fileSize);
				}
				else
					cout << "Can't create hash rule for " << 
					initialFile.string() << endl;
			}
		}
		else
			cout << initialFile.string() << " doesn't exist!" << endl;
	}
	catch (const fs::filesystem_error &e)
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
	catch (...)
	{
		cout << "Unknown exception" << endl;
	}
}

//checks whether file is a valid type as detirmined by the list 
//in the member variable executableTypes
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

			for (const auto &exeType : executableTypes)
				if (extension == exeType)
				{
					ruleCount++;
					threads.emplace_back(
						&HashRule::CreateNewHashRule,
						HashRule(),
						file.string(),
						secOption,
						fileSize);
				}
		}
	}
	catch (const fs::filesystem_error &e)
	{
		cout << e.what() << endl;
	}
	catch (...)
	{
		cout << "Unknown exception" << endl;
	}
}