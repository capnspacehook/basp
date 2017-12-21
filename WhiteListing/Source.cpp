#include "AppSecPolicy.hpp"
#include "SecPolicy.hpp"
#include "HashRule.hpp"
#include "Windows.h"

#include <filesystem>
#include <algorithm>
#include <iostream>	
#include <vector>
#include <regex>
#include <string>

using namespace std;
using namespace AppSecPolicy;
namespace fs = std::experimental::filesystem;

void CheckElevated();
inline void PrintInvalidMsg(const string&);
inline bool ValidFile(const string&);
bool CheckDirConflicts(vector<string>&);

int main(int argc, char *argv[])
{
	CheckElevated();

	/*SecPolicy s;
	s.EnumLoadedDLLs("c:\\users\\root\\downloads\\putty.exe");
	system("pause");*/

	string fullArgs;
	bool validOp = false;
	string programName = argv[0];
	vector<string> baseOptions = {
		"-b", "-w" , "-t", "-td", "-l", "-r", "/?" };
	vector<string> extndOptions = {
		"-e", "--admin" };
	
	//get the name of the program
	programName = programName.substr(
		programName.rfind("\\") + 1,
		programName.length());

	if (argc < 2)
		PrintInvalidMsg(programName);

	//build up 'fullArgs' to equal single string of entire argument
	string tempStr;
	fullArgs = programName;
	vector <string> args;
	regex fourSlashes("\\\\");
	for (int i = 1; i < argc; i++)
	{
		tempStr = argv[i];
		regex_replace(tempStr, fourSlashes, "\\");

		if (tempStr.back() == '\\')
			tempStr.pop_back();

		args.emplace_back(tempStr);
		fullArgs += " " + tempStr + " ";
	}

	//loop through all options 
	for (const auto &op : baseOptions)
		if (!fullArgs.find(programName + " " + op + " "))
			validOp = true;

	if (!validOp)
	{
		cout << "\nInvalid option";
		PrintInvalidMsg(programName);
	}
	else
	{
		SecPolicy policy;

		//if user only passed in one option only
		if (argc == 2)
		{
			if (argv[1] == baseOptions[4])
				policy.ListRules();

			if (argv[1] == baseOptions[6])
				PrintInvalidMsg(programName);
		}
		
		//if user passed in one option and one file
		else if (argc == 3)
		{
			if (argv[1] == baseOptions[0] && ValidFile(args[1]))
				policy.CreatePolicy(args[1], SecOption::BLACKLIST);

			else if (argv[1] == baseOptions[1] && ValidFile(args[1]))
				policy.CreatePolicy(args[1], SecOption::WHITELIST);

			else if (argv[1] == baseOptions[2] && ValidFile(args[1]))
			{
				auto exeFile = fs::path(args[1]);
				if (!fs::is_regular_file(exeFile))
				{
					cout << "\nFile must be executable";
					PrintInvalidMsg(programName);
				}
				else
				{
					policy.TempRun(exeFile.string());
				}
			}

			else if (argv[1] == baseOptions[3] && ValidFile(args[1]))
			{
				//we need to make sure parent directory is valid, and that
				//the file passed in is an executable
				auto exeFile = fs::path(args[1]);
				string parentDir = exeFile.parent_path().string();
				if (!ValidFile(parentDir))
				{
					cout << "\nInvalid parent directory";
					PrintInvalidMsg(programName);
				}
				else if (!fs::is_regular_file(exeFile))
				{
					cout << "\nFile must be executable";
					PrintInvalidMsg(programName);	
				}
				else
				{
					policy.TempRun(parentDir, exeFile.string());
				}
			}

			else if (argv[1] == baseOptions[5] && ValidFile(args[1]))
				policy.RemoveRules(args[1]);

			else if (argv[1] == baseOptions[6])
				PrintInvalidMsg(programName);

			else
			{
				cout << "\nInvalid file path";
				PrintInvalidMsg(programName);
			}
		}
		//if user passed multiple files/options
		else if (argc > 3)
		{
			int count = 0;
			vector<string> fileArgs;
			for (int i = 2; i < argc; i++)
			{
				if (ValidFile(argv[i]))
					fileArgs.emplace_back(argv[i]);

				else
					count++;
			}
			if (count == argc - 2)
				PrintInvalidMsg(programName);

			else if (argv[1] == baseOptions[0] || argv[1] == baseOptions[1])
			{
				if (CheckDirConflicts(fileArgs))
				{
					if (argv[1] == baseOptions[0])
						policy.CreatePolicy(fileArgs, SecOption::BLACKLIST);

					else if (argv[1] == baseOptions[1])
						policy.CreatePolicy(fileArgs, SecOption::WHITELIST);
				}
				else
				{
					cout << "\nFile arguments conflict; Please enter files/dirs that "
						<< "do not contain other files/dirs entered";
					PrintInvalidMsg(programName);
				}
			}

			else if (argv[1] == baseOptions[5])
			{
				if (CheckDirConflicts(fileArgs))
					policy.RemoveRules(fileArgs);

				else
				{
					cout << "\nFile arguments conflict; Please enter files/dirs that "
						<< "do not contain other files/dirs entered";
					PrintInvalidMsg(programName);
				}
				
			}

			else if (argv[3] == extndOptions[0])
			{
				if (!fs::is_directory(fileArgs[0]))
				{
					cout << "If you wish to temporarily run a single file, please "
						<< "specify only one file and omit the -e option" << endl;
					PrintInvalidMsg(programName);
				}

				policy.TempRun(fileArgs[0], fileArgs[1]);
			}

			else
			{
				cout << "\nInvalid args";
				PrintInvalidMsg(programName);
			}
		}
	}
	system("pause");
}

void CheckElevated()
{
	bool fRet = false;
	HANDLE hToken = NULL;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
	{
		TOKEN_ELEVATION Elevation;
		DWORD cbSize = sizeof(TOKEN_ELEVATION);
		if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize))
			fRet = Elevation.TokenIsElevated;
	}
	if (hToken)
		CloseHandle(hToken);

	if (!fRet)
	{
		cout << "This program requires administrator access to function correctly."
			<< "Please run this program again as an Administrator.\n";
		exit(-1);
	}
}

inline void PrintInvalidMsg(const string &programName)
{
	cout << "\nUsage: " << programName << " [-b] [-w] [-t [-e]] [-td] <file/dir>...\n"
		<< "Options:\n" 
		<< "-b\t\t" << "Disallow file(s)\n"
		<< "-w\t\t" << "Allow file(s)\n"
		<< "-t\t\t" << "Run a program without creating an allow rule for it\n"
		<< "-e\t\t" << "If used with -t, specifies which program to execute after the files\n"
		<< "\t\tin the dir specified after -t are temorarily whitelisted\n"
		<< "-td\t\t" << "Temporarily whitelist the file and all the files in it's directory\n"
		<< "Advanced options:\n\n";

	exit(-1);
}

inline bool ValidFile(const string& str)
{
	return fs::exists(str);
}

bool CheckDirConflicts(vector<string> &files)
{
	bool noConflicts = true;
	vector<fs::path> paths;
	for (const auto &file : files)
			paths.emplace_back(file);

	sort(paths.begin(), paths.end(),
		[](fs::path p1, fs::path p2) 
	{ return p1.string().length() < p2.string().length(); });

	fs::path temp;
	for (int i = 1; i < paths.size(); i++)
	{
		temp = paths[i];
		while (paths[i].root_path() != temp.parent_path())
		{
			if (paths[0] == temp.parent_path())
			{
				noConflicts = false;
				break;
			}
			else
				temp = temp.parent_path();
		}
				
		if (!noConflicts)
			break;
	}
	
	return noConflicts;
}