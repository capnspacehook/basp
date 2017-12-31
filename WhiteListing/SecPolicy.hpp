#include "AppSecPolicy.hpp"
#include "DataFileManger.hpp"

#include <filesystem>
#include <iostream>
#include <memory>
#include <atomic>
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
		explicit SecPolicy() noexcept {};
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

	protected:
		friend class HashRule;

		//statistical variables
		static std::atomic_uintmax_t createdRules;
		static std::atomic_uintmax_t switchedRules;
		static std::atomic_uintmax_t skippedRules;
		static std::atomic_uintmax_t removedRules;

	private:
		void CheckGlobalSettings();
		bool SetPrivileges(const std::string&, bool);
		void StartTimer()
		{
			startTime = std::chrono::high_resolution_clock::now();
		}
		void EnumAttributes(const std::string&);
		void EnumDirContents(const fs::path&, uintmax_t&);
		void DeleteRules(const fs::path&);
		void CheckValidType(const fs::path&, const uintmax_t&);
		void PrintStats() const;
		void ApplyChanges(bool);

		std::string passwordGuess;
		DataFileManager dataFileMan;

		//program settings
		unsigned dllWaitSecs = 3;

		//file extensions that will be enforced
		std::vector<std::string> executableTypes;

		bool updatedRules = false;
		bool tempRuleCreation = false;
		bool ruleRemoval = false;

		const unsigned maxHardwareThreads = 
			std::thread::hardware_concurrency();
		std::vector<std::thread> threads;

		SecOption secOption;
		RuleType ruleType;

		std::vector<UserRule> enteredRules;
		
		std::vector<std::shared_ptr<RuleData>> createdRulesData;
		std::vector<std::shared_ptr<RuleData>> switchedRulesData;
		std::vector<std::shared_ptr<RuleData>> removededRulesData;
		
		std::chrono::time_point<std::chrono::steady_clock> startTime;
	};
}