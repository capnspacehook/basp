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
		explicit SecPolicy(std::string &&prgmName, std::string &&pwd, bool update, bool lstRules, bool lstAll)
			: updateRules(update), listRules(lstRules), listAllRules(lstAll), programName(std::move(prgmName)), dataFileMan(programName)
		{
			dataFileMan.VerifyPassword(std::move(pwd));
			
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
					ListRules();

				PrintStats(diff);
			}

			else if (listRules || listAllRules)
				ListRules();
		}

		void CreatePolicy(const std::vector<std::string> &paths,
			const SecOption &op, RuleType = RuleType::HASHRULE);
		void DefaultPolicy();
		void TempRun(const std::string &path);
		void TempRun(const std::string &dir, const std::string &exeFile);
		void UpdateRules(const std::vector<std::string>&);
		void RemoveRules(std::vector<std::string> &paths);
		void CheckRules();
		void ListRules() const;
		void ChangePassword();

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
		static moodycamel::ConcurrentQueue<RmRuleInfo> removeQueue;
		static moodycamel::ConcurrentQueue<RuleData> ruleCheckQueue;
		static moodycamel::ConcurrentQueue<std::string> ruleStringQueue;

	private:
		void CheckGlobalSettings();
		inline void StartTimer() noexcept
		{
			startTime = std::chrono::high_resolution_clock::now();
		}
		void ProcessRules();
		void PrintStats(TimeDiff) const;
		void ApplyChanges(bool);

		std::string programName;
		bool updateRules = false;
		bool ruleCheck = false;
		bool listRules = false;
		
		bool listAllRules = false;
		bool ruleRemoval = false;
		bool tempRuleCreation = false;

		DataFileManager dataFileMan;

		SecOption secOption;
		RuleType ruleType;

		std::vector<std::string> executableTypes;

		std::vector<std::string> scriptingDeps = { "cscript.exe", "dispex.dll", 
			"jscript.dll", "jscript9.dll", "jscript9diag.dll", "scrobj.dll", "scrrun.dll", 
			"vbscript.dll", "wcscript.exe", "wdispex.dll", "wjscript.dll", "wmsscript.ocx", 
			"wscript.exe", "wscrobj.dll", "wscrrun.dll", "wshcon.dll", "wshext.dll", "wshom.ocx", 
			"wvbscript.dll", "wwscript.exe", "wwshcon.dll", "wwshext.dll", "wwshom.ocx" };
			
		std::vector<std::string> bypassFiles = { "addinprocess.exe", "addinprocess32.exe",
			"addinutil.exe", "bash.exe", "bginfo.exe", "cdb.exe", "csi.exe", "dbghost.exe",
			"dbgsvc.exe", "dnx.exe", "fsi.exe", "fsiAnyCpu.exe", "kd.exe", "ntkd.exe",
			"lxssmanager.dll", "msbuild.exe", "mshta.exe", "ntsd.exe", "pubprn.vbs",
			"rcsi.exe", "slmgr.vbs", "system.management.automation.dll", "te.exe",
			"windbg.exe", "winrm.vbs" };

		//Full List
		/*"atbroker.exe", "bginfo.exe",
		"cdb.exe", "cmstp.exe", "csi.exe", "dfsvc.exe", "dnx.exe", "forfiles.exe",
		"fsi.exe", "ieexec.exe", "infdefaultinstall.exe", "installutil.exe",
		"mavinject32.exe", "msbuild.exe", "msdt.exe", "mshta.exe", "msiexec.exe",
		"msxsl.exe", "odbcconf.exe", "presentationhost.exe", "pubprn.vbs",
		"rcsi.exe", "regasm.exe", "regsvcs.exe", "regsvr32.exe", "rundll32.exe",
		"runscripthelper.exe", "slmgr.vbs", "syncappvpublishingserver.exe", "te.exe",
		"tracker.exe" "winrm.vbs", "winword.exe", "wmic.exe", "xwizard.exe"*/ 

		bool justListing = true;
		bool whitelistedBASP = false;
		bool creatingSingleRule = false;
		bool creatingDefaultPolicy = false;
		std::vector<std::thread> ruleProducers;
		std::vector<std::thread> ruleConsumers;
		const unsigned maxThreads = std::thread::hardware_concurrency();
		const unsigned initThreadCnt = maxThreads / 2;

		std::vector<UserRule> enteredRules;
		
		RuleDataPtr baspRule;

		std::vector<RuleDataPtr> createdRulesData;
		std::vector<RuleDataPtr> updatedRulesData;
		std::vector<RuleDataPtr> removededRulesData;
		
		std::chrono::time_point<std::chrono::steady_clock> startTime;
	};
}