#include "AppSecPolicy.hpp"
#include "DataFileManger.hpp"

#include <filesystem>
#include <iostream>
#include <chrono>
#include <thread>
#include <string>
#include <vector>
#include <tuple>
#pragma once

namespace fs = std::experimental::filesystem;

namespace AppSecPolicy
{
	class SecPolicy
	{
	public:
		explicit SecPolicy()
		{
			CheckGlobalSettings();
		};
		~SecPolicy()
		{
			//wait for all threads to finish
			for (auto &t : threads)
				t.join();

			ApplyChanges(true);
			PrintStats();
		}

		void CreatePolicy(const std::string &path,
			const SecOption &op, RuleType = RuleType::HASHRULE);
		void CreatePolicy(const std::vector<std::string> &paths,
			const SecOption &op, RuleType = RuleType::HASHRULE);
		void TempRun(const std::string &path);
		void TempRun(const std::string &dir, const std::string &exeFile);
		void EnumLoadedDLLs(const std::string &exeFile);

	private:
		void CheckGlobalSettings() const;
		bool SetPrivileges(const std::string&, bool);
		void EnumAttributes(const std::string&);
		void EnumDirContents(const fs::path&, long long&);
		void CheckValidType(const fs::path&, const long long&);
		void PrintStats() const;
		void ApplyChanges(bool);

		DataFileManager dataFileMan;

		//program settings
		float dllWaitSecs = 3;

		//global policy settings
		int authenticodeEnabled;	//apply certificate rules or not
		int defaultLevel;			//allow or deny everything by default

		//file extensions that will be enforced
		std::vector<std::string> executableTypes = {
			"ADE", "ADP", "APPLICATION", "BAS", "BAT", "BGI", "CHM", "CMD", "COM", 
			"CPL", "CRT", "DIAGCAB", "DLL", "EXE", "HLP", "HTA", "INF", "INS", 
			"ISP", "JS", "JSE", "LNK", "MDB", "MDE", "MSC", "MSI", "MSP", "MST", 
			"OCX", "PCD", "PIF", "PS1", "PS2", "PSM", "REG", "SCR", "SCT", "SHS", 
			"URL", "VB", "VBE", "VBS", "VBSCRIPT", "WSC", "XAML", "XBAP", "XPI" };

		int policyScope;			//controls if policy applies to admins
		int transparentEnabled;		//controls if dlls are enforced or not
		
		bool tempRuleCreation = false;
		std::vector<std::thread> threads;
		SecOption secOption;
		RuleType ruleType;
		RuleData createdRulesData;
		RuleData switchedRulesData;

		//statistical variables
		int createdRules = 0;
		int switchedRules = 0;
		int skippedRules = 0;
		std::chrono::time_point<std::chrono::steady_clock> startTime =
			std::chrono::high_resolution_clock::now();
	};
}