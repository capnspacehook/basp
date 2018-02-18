#include "AppSecPolicy.hpp"
#include "DataFileManger.hpp"

#include "include\concurrentqueue.h"

#include <iostream>
#include <atomic>
#include <chrono>
#include <thread>
#pragma once

namespace fs = std::experimental::filesystem;

namespace AppSecPolicy
{
	using TimeDiff = std::common_type_t<std::chrono::nanoseconds, std::chrono::nanoseconds>;

	class SecPolicy
	{
	public:
		explicit SecPolicy(std::string &prgmName, std::string& pwd, bool lstRules, bool lstAll)
			: listRules(lstRules), listAllRules(lstAll), dataFileMan(prgmName)
		{
			dataFileMan.VerifyPassword(pwd);
			
			CheckGlobalSettings();
			StartTimer();
		}
		~SecPolicy()
		{
			if (!justListing)
			{
				ApplyChanges(true);
				const auto diff = std::chrono::high_resolution_clock::now() - startTime;

				if (listRules || listAllRules)
				{
					std::cout << '\n';
					ListRules();
				}

				PrintStats(diff);
			}

			else if (listRules || listAllRules)
				ListRules();
		}

		void CreatePolicy(const std::vector<std::string> &paths,
			const SecOption &op, RuleType = RuleType::HASHRULE);
		void TempRun(const std::string &path);
		void TempRun(const std::string &dir, const std::string &exeFile);
		void RemoveRules(std::vector<std::string> &paths);
		void CheckRules();
		void ListRules() const;

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
		static std::atomic_uint producerCount;
		static std::atomic_uint doneProducers;
		static std::atomic_uint doneConsumers;
		static std::atomic_bool fileCheckingNotDone;
		static moodycamel::ConcurrentQueue<DirInfo> dirItQueue;
		static moodycamel::ConcurrentQueue<FileInfo> fileCheckQueue;
		static moodycamel::ConcurrentQueue<RuleAction> ruleQueue;
		static moodycamel::ConcurrentQueue<RuleData> ruleCheckQueue;
		static moodycamel::ConcurrentQueue<std::string> ruleStringQueue;

	private:
		void CheckGlobalSettings();
		inline void StartTimer() noexcept
		{
			startTime = std::chrono::high_resolution_clock::now();
		}
		void StartProcessing(const std::vector<std::string>&);
		void DeleteRules(const std::vector<std::string>&);
		void ModifyRules();
		void PrintStats(TimeDiff) const;
		void ApplyChanges(bool);

		bool ruleCheck = false;
		bool listRules = false;
		bool justListing = true;
		bool listAllRules = false;
		DataFileManager dataFileMan;

		SecOption secOption;
		RuleType ruleType;

		//program settings
		unsigned dllWaitSecs = 3;

		bool ruleRemoval = false;
		bool tempRuleCreation = false;

		std::vector<std::string> executableTypes;

		bool creatingSingleRule = false;
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