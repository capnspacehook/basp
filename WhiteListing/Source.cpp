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
bool CheckDirConflicts(const vector<string>&);
void GPUpdate();

int main(int argc, char *argv[])
{
	CheckElevated();

	string args;
	bool validOp = false;
	bool tempRules = false;
	string programName = argv[0];
	vector<string> baseOptions = {
		"-b", "-w" , "-t", "-td", "-d", "/?" };
	vector<string> extndOptions = {
		"-e", "--admin" };
	
	//get the name of the program
	programName = programName.substr(
		programName.rfind("\\") + 1,
		programName.length());

	if (argc < 3)
		PrintInvalidMsg(programName);

	//build up 'args' to equal single string of entire argument
	args = programName;
	for (int i = 1; i < argc; i++)
		args += " " + (string)argv[i] + " ";

	//loop through all options 
	for (const auto &op : baseOptions)
		if (!args.find(programName + " " + op + " "))
			validOp = true;

	if (!validOp)
	{
		cout << "\nInvalid option";
		PrintInvalidMsg(programName);
	}
	else
	{
		SecPolicy policy;
		
		//if user passed in one option and one file
		if (argc == 3)
		{
			//foward slashes are escaped, so the compiler interprets this to "\\\\"
			regex fourSlashes("\\\\\\\\");
			string ruleFile = regex_replace(argv[2], fourSlashes, "\\");

			if (argv[1] == baseOptions[0] && ValidFile(ruleFile))
				policy.CreatePolicy(ruleFile, SecOptions::BLACKLIST);

			else if (argv[1] == baseOptions[1] && ValidFile(ruleFile))
				policy.CreatePolicy(ruleFile, SecOptions::WHITELIST);

			else if (argv[1] == baseOptions[2] && ValidFile(ruleFile))
			{
				auto exeFile = fs::path(ruleFile);
				if (!fs::is_regular_file(exeFile))
				{
					cout << "\nFile must be executable";
					PrintInvalidMsg(programName);
				}
				else
				{
					tempRules = true;
					policy.TempRun(exeFile.string());
				}
			}

			else if (argv[1] == baseOptions[3] && ValidFile(ruleFile))
			{
				//we need to make sure parent directory is valid, and that
				//the file passed in is an executable
				auto exeFile = fs::path(ruleFile);
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
					tempRules = true;
					policy.TempRun(parentDir, exeFile.string());
				}
			}

			else if (argv[1] == baseOptions[5])
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
			regex fourSlashes("\\\\\\\\");
			for (int i = 2; i < argc; i++)
			{
				if (ValidFile(argv[i]))
					fileArgs.emplace_back(
						regex_replace(
							argv[i], 
							fourSlashes, 
							"\\"));

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
						policy.CreatePolicy(fileArgs, SecOptions::BLACKLIST);

					else if (argv[1] == baseOptions[1])
						policy.CreatePolicy(fileArgs, SecOptions::WHITELIST);
				}
				else
				{
					cout << "File arguments conflict; Please enter files/dirs that "
						<< "do not contain other files/dirs entered";
					PrintInvalidMsg(programName);
				}
			}

			else if (argv[3] == extndOptions[0])
			{
				tempRules = true;
				policy.TempRun(fileArgs[0], fileArgs[1]);
			}

			else
			{
				cout << "Invalid args";
				PrintInvalidMsg(programName);
			}
		}
	}
	if (!tempRules)
		GPUpdate();
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
		<< "-td\t\t" << "Temporarily whitelist the file and all the files in it's directory\n"
		<< "Advanced options:\n"
		<< "-e\t\t" << "If used with -t, specifies which program to execute after the files\n"
		<< "\t\tin the dir specified after -t are temorarily whitelisted\n\n";

	exit(-1);
}

inline bool ValidFile(const string& str)
{
	return fs::exists(str);
}

bool CheckDirConflicts(const vector<string> &files)
{
	bool noConflicts = true;
	vector<fs::path> paths;
	for (int i = 0; i < files.size(); i++)
		paths.emplace_back(files[i]);

	sort(paths.begin(), paths.end(),
		[](fs::path p1, fs::path p2) 
	{ return p1.string().length() < p2.string().length(); });

	fs::path temp;
	for (int i = 0; i < paths.size(); i++)
	{
		if (!noConflicts)
			break;

		for (int j = 0; j < paths.size(); j++)
		{
			if (j == i)
				continue;
			else
			{
				temp = paths[j];
				while (paths[j].root_path() != temp.parent_path())
				{
					if (paths[i] == temp.parent_path())
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
		}
	}
	
	return noConflicts;
}

//initiate a Group Policy Update after we're done
void GPUpdate() {
	// additional information
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	SecureZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	SecureZeroMemory(&pi, sizeof(pi));

	cout << endl;

	// start the program up
	CreateProcess("C:\\Windows\\System32\\gpupdate.exe",   // the path
		" /target:computer",        // Command line
		NULL,           // Process handle not inheritable
		NULL,           // Thread handle not inheritable
		FALSE,          // Set handle inheritance to FALSE
		0,              // No creation flags
		NULL,           // Use parent's environment block
		NULL,           // Use parent's starting directory 
		&si,            // Pointer to STARTUPINFO structure
		&pi             // Pointer to PROCESS_INFORMATION structure (removed extra parentheses)
	);

	Sleep(7500);
	// Close process and thread handles. 
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
}