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

			if (showHelp || !(blacklisting || whitelisting || updatingRules || removingRules || listRules || listAllRules || !tempAllowFile.empty() || !tempAllowDir.empty() || checkRules || changePassword))
			{
				std::cout << R"(
	     ___          ___          ___                  
	    /  /\        /  /\        /  /\         ___     
	   /  /::\      /  /::\      /  /::\       /  /\    
	  /  /:/\:\    /  /:/\:\    /__/:/\:\     /  /::\   
	 /  /::\ \:\  /  /::\ \:\  _\_ \:\ \:\   /  /:/\:\  
	/__/:/\:\_\:|/__/:/\:\_\:\/__/\ \:\ \:\ /  /::\ \:\ 
	\  \:\ \:\/:/\__\/  \:\/:/\  \:\ \:\_\//__/:/\:\_\:\
	 \  \:\_\::/      \__\::/  \  \:\_\:\  \__\/  \:\/:/
	  \  \:\/:/       /  /:/    \  \:\/:/       \  \::/ 
	   \__\::/       /__/:/      \  \::/         \__\/  
	                 \__\/        \__\/                 )" << "\n\n";

				std::cout << "Better Application Security Policy\n"
					<< "https://github.com/capnspacehook/Better-Application-Security-Policy\n\n"
					<< parser << '\n'
					<< "Created by Andrew LeFevre";

				std::exit(-1);
			}

			if ((whitelisting || blacklisting || removingRules || updatingRules) && fileArgs.empty())
				PrintError("No files or dirs entered");

			if (listAllRules && !listRules)
				PrintError("'-a' option requires '-l'");

			if (!tempAllowFile.empty())
			{
				if (!fs::exists(tempAllowFile))
					PrintError("File entered for '-t' is not valid");

				else if (!fs::is_regular_file(tempAllowFile))
					PrintError("An executable file must be entered for '-t' option");

				ToLower(tempAllowFile);
			}

			if (!tempAllowDir.empty())
			{
				if (tempAllowExe.empty())
					PrintError("'--temp-allow-dir' option requires '--temp-execute-file' option");

				else if (!fs::exists(tempAllowDir))
					PrintError("File entered for '--temp-allow-dir' is not valid");

				else if (!fs::is_directory(tempAllowDir))
					PrintError("A directory must be entered for '--temp-allow-dir'");

				ToLower(tempAllowDir);
			}

			if (!tempAllowExe.empty())
			{
				if (tempAllowDir.empty())
					PrintError("'--temp-execute-file' option requires '--temp-allow-dir' option");

				else if (!fs::exists(tempAllowExe))
					PrintError("File entered for '--temp-execute-file' is not valid");

				else if (!fs::is_regular_file(tempAllowExe))
					PrintError("An executable file must be entered for '--temp-execute-file' option");

				ToLower(tempAllowExe);
			}

			if (tempAllowParentDir)
			{
				if (tempAllowFile.empty())
					PrintError("'-d' option requires '-t' option");

				parentDir = fs::path(tempAllowFile).parent_path().string();

				if (!fs::exists(parentDir))
					PrintError("Parent directory of file entered for '-d' is not valid");
			}

			if (!tempAllowFile.empty() && !tempAllowDir.empty())
				PrintError("'-t' and '-d' cannot be used with '--temp-allow-dir' and '--temp-execute-file'");

			if ((whitelisting && blacklisting) || (whitelisting && removingRules) || (blacklisting && removingRules))
				PrintError("Options '-w', '-b', and '-r' are mutually exclusive");

			if (removingRules && updatingRules)
				PrintError("'-u' cannot be used with 'r'");

			if (executeAsAdmin && !(tempAllowFile.empty() || tempAllowDir.empty() || tempAllowExe.empty()))
				PrintError("'--admin' is only valid when used with '-t' or '--temp-allow-dir' and '--temp-execute-file'");

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
		bool updatingRules = false;
		bool removingRules = false;
		std::string tempAllowFile;
		std::string tempAllowDir;
		std::string tempAllowExe;
		std::string parentDir;
		bool tempAllowParentDir = false;
		bool checkRules = false;
		std::string password;
		bool executeAsAdmin = false;
		bool changePassword = false;
		std::vector<std::string> fileArgs;

	private:
		void ToLower(std::string& fileName) noexcept
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
			| clara::detail::Opt(whitelisting)
			["-w"]["--whitelist"]
			("Create rules that allow files")
			| clara::detail::Opt(blacklisting)
			["-b"]["--blacklist"]
			("Create rules that block files")
			| clara::detail::Opt(updatingRules)
			["-u"]["--update-rules"]
			("Scan for changes of files for created rules and update rules if files change.  If used with '-b' or '-w', rules already created will be updated")
			| clara::detail::Opt(removingRules)
			["-r"]["--remove-rules"]
			("Remove already created rules")
			| clara::detail::Opt(tempAllowFile, "executable")
			["-t"]["--temp-allow-file"]
			("Temporarily allow and execute blocked files. Files will be reblocked immediately after execution")
			| clara::detail::Opt(tempAllowParentDir)
			["-d"]["--temp-allow-parent-dir"]
			("Requires '-t'. When used, the parent directory of the executable specified by '-t' is whitelisted before temporary execution. Useful if DLLs or other dependencies need to be whitelisted for program to run")
			| clara::detail::Opt(tempAllowDir, "directory")
			["--temp-allow-dir"]
			("Temporarily allow a directory")
			| clara::detail::Opt(tempAllowExe, "executable")
			["--temp-execute-file"]
			("Specify a dir to temporarily allow with '--temp-allow-dir', and use '--temp-execute-file' to specify what file to execute")
			| clara::detail::Opt(checkRules)
			["-k"]["--check-rules"]
			("Check for any modifications to created files in the registry. Rules will automactically be fixed if modified")
			| clara::detail::Opt(listRules)
			["-l"]["--list"]
			("Displays created rules")
			| clara::detail::Opt(listAllRules)
			["-a"]["--list-all"]
			("Requires '-l'. Displays every created rule individually")
			| clara::detail::Opt(password, "password")
			["--password"]
			("Attempts to unlock BASP with password")
			| clara::detail::Opt(changePassword)
			["--change-password"]
			("Change the password for BASP")
			| clara::detail::Opt(executeAsAdmin)
			["--admin"]
			("Executes a temporarily allowed file as Administrator")
			| clara::detail::Arg(fileArgs, "files/dirs");
	};
}