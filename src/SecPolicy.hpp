#include "AppSecPolicy.hpp"
#include "DataFileManger.hpp"

#include "include\concurrentqueue.h"

#include <atomic>
#include <chrono>
#include <thread>
#pragma once

namespace fs = std::experimental::filesystem;

namespace AppSecPolicy
{
	class SecPolicy
	{
	public:
		SecPolicy() = default;
		~SecPolicy()
		{
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
		void RemoveRules(std::vector<std::string> &paths);
		void EnumLoadedDLLs(const std::string &exeFile);
		void ListRules();

	protected:
		friend class HashRule;
		friend class RuleProducer;
		friend class RuleConsumer;


		//statistical variables
		static std::atomic_uintmax_t createdRules;
		static std::atomic_uintmax_t switchedRules;
		static std::atomic_uintmax_t updatedRules;
		static std::atomic_uintmax_t skippedRules;
		static std::atomic_uintmax_t removedRules;
		
		//variables for managing threads
		static std::atomic_uint doneProducers;
		static std::atomic_uint doneConsumers;
		static std::atomic_bool fileCheckingNotDone;
		static moodycamel::ConcurrentQueue<DirInfo> dirItQueue;
		static moodycamel::ConcurrentQueue<FileInfo> fileCheckQueue;
		static moodycamel::ConcurrentQueue<RuleAction> ruleQueue;

	private:
		void CheckGlobalSettings();
		bool SetPrivileges(const std::string&, bool);
		inline void StartTimer() noexcept
		{
			startTime = std::chrono::high_resolution_clock::now();
		}
		void EnumAttributes(const std::string&);
		void DeleteRules(const std::vector<std::string>&);
		void ModifyRules();
		void PrintStats() const;
		void ApplyChanges(bool);

		std::string passwordGuess;
		DataFileManager dataFileMan;

		SecOption secOption;
		RuleType ruleType;

		//program settings
		unsigned dllWaitSecs = 3;

		bool ruleRemoval = false;
		bool tempRuleCreation = false;

		std::vector<std::string> executableTypes;

		std::vector<std::thread> ruleProducers;
		std::vector<std::thread> ruleConsumers;
		const unsigned maxThreads = std::thread::hardware_concurrency();
		const unsigned initThreadCnt = maxThreads / 2;

		std::vector<UserRule> enteredRules;
		
		std::vector<RuleDataPtr> createdRulesData;
		std::vector<RuleDataPtr> updatedRulesData;
		std::vector<RuleDataPtr> removededRulesData;
		
		std::chrono::time_point<std::chrono::steady_clock> startTime;
	};
}