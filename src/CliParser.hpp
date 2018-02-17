#include <string>
#include <vector>
#include <iostream>
#include <filesystem>

#include "include\clara.hpp"
#pragma once

namespace AppSecPolicy
{
	class CliParser
	{
	public:
		explicit CliParser(int argc, char* argv[])
		{
			auto result = parser.parse(clara::detail::Args(argc, argv));

			if (!result)
				PrintError(result.errorMessage().c_str());

			else if (showHelp || !(blacklisting || whitelisting || removingRules || listRules || listAllRules || !tempAllowFile.empty() || !tempAllowDir.empty() || !tempAllowParentDir.empty() || checkRules))
			{
				std::cout << "Better Application Security Policy\n"
					<< "https://github.com/capnspacehook/Better-Application-Security-Policy\n\n"
					<< parser << '\n'
					<< "Created by Andrew LeFevre";

				std::exit(-1);
			}

			else if ((whitelisting || blacklisting || removingRules) && fileArgs.empty())
				PrintError("No files or dirs entered");

			else if (!tempAllowFile.empty())
			{
				if (!fs::exists(tempAllowFile))
					PrintError("File entered for '-t' is not valid");

				else if (!fs::is_regular_file(tempAllowFile))
					PrintError("An executable file must be entered for '-t' option");
			
				ToLower(tempAllowFile);
			}

			else if (!tempAllowDir.empty())
			{
				if (tempAllowExe.empty())
					PrintError("'-d' option requires '-e' option");

				else if (!fs::exists(tempAllowDir))
					PrintError("File entered for '-d' is not valid");

				else if (!fs::is_directory(tempAllowDir))
					PrintError("A directory must be entered for '-d'");

				ToLower(tempAllowDir);
			}

			else if (!tempAllowExe.empty())
			{
				if (tempAllowDir.empty())
					PrintError("'-e' option requires '-d' option");

				else if (!fs::exists(tempAllowExe))
					PrintError("File entered for '-e' is not valid");

				else if (!fs::is_regular_file(tempAllowExe))
					PrintError("An executable file must be entered for '-e' option");
				
				ToLower(tempAllowExe);
			}

			else if (!tempAllowParentDir.empty())
			{
				parentDir = fs::path(tempAllowParentDir).parent_path().string();

				if (!fs::exists(tempAllowParentDir))
					PrintError("File entered for '-a' is not valid");

				else if (!fs::is_regular_file(tempAllowParentDir))
					PrintError("An executable file must be entered for '-a' option");

				else if (!fs::exists(parentDir))
					PrintError("Parent directory of file entered for '-a' is not valid");

				ToLower(tempAllowParentDir);
			}

			else if (!tempAllowParentDir.empty() && (!tempAllowFile.empty() || !tempAllowDir.empty() || !tempAllowExe.empty()))
				PrintError("-a cannot be used with '-t', '-d', or '-e'");

			else if ((whitelisting && blacklisting) || (whitelisting && removingRules) || (blacklisting && removingRules))
				PrintError("Options '-w', '-b', and '-r' are mutually exclusive");

			else if (executeAsAdmin && !(tempAllowFile.empty() || tempAllowDir.empty() || tempAllowExe.empty()))
				PrintError("'--admin' is only valid when used with '-t', '-d' and '-e', or ");

			for (auto &file : fileArgs)
			{
				if (file.back() == '\\')
					file.pop_back();

				if (!fs::exists(file))
					PrintError("File(s) entered are not valid");
				
				ToLower(file);
			}

			if (CheckFileConflicts(fileArgs))
				PrintError("File arguments conflict; Please enter files/dirs that do not contain other files/dirs entered");
		}

		std::string programName;
		bool showHelp = false;
		bool listRules = false;
		bool listAllRules = false;
		bool whitelisting = false;
		bool blacklisting = false;
		bool removingRules = false;
		std::string tempAllowFile;
		std::string tempAllowDir;
		std::string tempAllowExe;
		std::string parentDir;
		std::string tempAllowParentDir;
		bool checkRules = false;
		std::string password;
		bool executeAsAdmin = false;
		std::vector<std::string> fileArgs;

	private:
		void ToLower(std::string& fileName)
		{
			for (auto &letter : fileName)
				letter = std::move(tolower(letter));
		}
		inline void PrintError(const char* error)
		{
			std::cout << "Command line error: " << error << "\n\n";

			std::exit(-1);
		}
		bool CheckFileConflicts(std::vector<std::string> &files)
		{
			bool fileConflicts = false;
			std::vector<fs::path> paths;
			for (const auto &file : files)
				paths.emplace_back(file);

			std::sort(paths.begin(), paths.end(),
				[](fs::path p1, fs::path p2)
				{ return p1.string().length() < p2.string().length(); });

			fs::path temp;
			for (int i = 1; i < paths.size() && fileConflicts; i++)
			{
				temp = paths[i];
				while (paths[i].root_path() != temp.parent_path())
				{
					if (paths.front() == temp.parent_path())
					{
						fileConflicts = true;
						break;
					}

					else
						temp = temp.parent_path();
				}
			}

			if (!fileConflicts)
				std::sort(files.begin(), files.end());

			return fileConflicts;
		}

		const clara::detail::Parser parser =
			clara::detail::ExeName(programName)
			| clara::detail::Help(showHelp)
			| clara::detail::Opt(listRules)
			["-l"]["--list"]
			("Display created rules")
			| clara::detail::Opt(listAllRules)
			["--list-all"]
			("Display every created rule individually")
			| clara::detail::Opt(whitelisting)
			["-w"]["--whitelist"]
			("Create rules that allow files")
			| clara::detail::Opt(blacklisting)
			["-b"]["--blacklist"]
			("Create rules that block files")
			| clara::detail::Opt(removingRules)
			["-r"]["--remove"]
			("Remove already created rules")
			| clara::detail::Opt(tempAllowFile, "executable")
			["-t"]["--temp-allow-file"]
			("Temporarily allow and execute blocked files. Files will be reblocked immediately after execution")
			| clara::detail::Opt(tempAllowDir, "directory")
			["-d"]["--temp-allow-dir"]
			("Temporarily allow a directory")
			| clara::detail::Opt(tempAllowExe, "executable")
			["-e"]["--temp-execute-file"]
			("Specify a dir to temporarily allow with -d, and use -e to specify what file to execute")
			| clara::detail::Opt(tempAllowParentDir, "executable")
			["-a"]["--auto-allow-execute"]
			("Temporarily allow dir of file entered, then execute file")
			| clara::detail::Opt(checkRules)
			["--check-rules"]
			("Check for any modifications to created files in the registry. Rules will automactically be fixed if modified")
			| clara::detail::Opt(password, "password")
			["--password"]
			("Attempts to unlock BASP with password")
			| clara::detail::Opt(executeAsAdmin)
			["--admin"]
			("Executes a temporarily allowed file as Administrator")
			| clara::detail::Arg(fileArgs, "files/dirs");
	};
}