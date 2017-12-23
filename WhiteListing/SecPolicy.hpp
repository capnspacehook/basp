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
			
		};
		~SecPolicy()
		{
			//wait for all threads to finish
			for (auto &t : threads)
				t.join();

			ApplyChanges(true);
			PrintStats();
		}

		void SetPasswordGuess(std::string& pwd)
		{
			passwordGuess = std::move(pwd);
		}

		void CreatePolicy(const std::string &path,
			const SecOption &op, RuleType = RuleType::HASHRULE);
		void CreatePolicy(const std::vector<std::string> &paths,
			const SecOption &op, RuleType = RuleType::HASHRULE);
		void TempRun(const std::string &path);
		void TempRun(const std::string &dir, const std::string &exeFile);
		void RemoveRules(const std::string &path);
		void RemoveRules(const std::vector<std::string> &paths);
		void EnumLoadedDLLs(const std::string &exeFile);
		void ListRules();

	private:
		void CheckGlobalSettings();
		bool SetPrivileges(const std::string&, bool);
		void StartTimer()
		{
			startTime = std::chrono::high_resolution_clock::now();
		}
		void EnumAttributes(const std::string&);
		void EnumDirContents(const fs::path&, uintmax_t&);
		void DeleteRule(const fs::path&);
		void CheckValidType(const fs::path&, const uintmax_t&);
		void PrintStats() const;
		void ApplyChanges(bool);

		std::string passwordGuess;
		DataFileManager dataFileMan;

		//program settings
		unsigned dllWaitSecs = 3;

		//file extensions that will be enforced
		std::vector<std::string> executableTypes;

		bool tempRuleCreation = false;
		bool ruleRemoval = false;

		std::vector<std::thread> threads;

		SecOption secOption;
		RuleType ruleType;

		RuleData createdRulesData;
		RuleData switchedRulesData;
		RuleData removedRulesData;

		//statistical variables
		std::size_t createdRules = 0;
		std::size_t switchedRules = 0;
		std::size_t skippedRules = 0;
		std::size_t removedRules = 0;
		std::chrono::time_point<std::chrono::steady_clock> startTime;
	};
}