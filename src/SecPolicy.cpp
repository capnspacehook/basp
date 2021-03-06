#include "RuleProducer.hpp"
#include "RuleConsumer.hpp"
#include "SecPolicy.hpp"
#include "HashRule.hpp"
#include "Windows.h"

#include "include\WinReg.hpp"

#include <exception>
#include <algorithm>
#include <iostream>
#include <sstream>

using namespace std;
using namespace moodycamel;
using namespace AppSecPolicy;
namespace fs = std::experimental::filesystem;

atomic_uintmax_t SecPolicy::createdRules = 0;
atomic_uintmax_t SecPolicy::switchedRules = 0;
atomic_uintmax_t SecPolicy::updatedRules = 0;
atomic_uintmax_t SecPolicy::skippedRules = 0;
atomic_uintmax_t SecPolicy::removedRules = 0;

atomic_uint SecPolicy::producerCount = 0;
atomic_uint SecPolicy::doneProducers = 0;
atomic_uint SecPolicy::doneConsumers = 0;
atomic_bool SecPolicy::fileCheckingNotDone = true;
ConcurrentQueue<DirInfo> SecPolicy::dirItQueue;
ConcurrentQueue<FileInfo> SecPolicy::fileCheckQueue;
ConcurrentQueue<RuleAction> SecPolicy::ruleQueue;
ConcurrentQueue<RmRuleInfo> SecPolicy::removeQueue;
ConcurrentQueue<RuleData> SecPolicy::ruleCheckQueue;
ConcurrentQueue<string> SecPolicy::ruleStringQueue;

//creates hash rules for each of the files in the vector 'paths'
void SecPolicy::CreatePolicy(const vector<string> &paths, const SecOption &op,
	RuleType rType)
{
	justListing = false;
	secOption = op;
	ruleType = rType;

	for (const auto &file : paths)
	{
		enteredRules.emplace_back(
			secOption, ruleType, file);
	}

	try
	{
		vector<fs::path> regFiles;
		vector<fs::path> directories;
		for (const auto &file : paths)
		{
			fs::path filePath(file);
			filePath.make_preferred();

			if (fs::is_regular_file(filePath))
				regFiles.emplace_back(filePath);

			else if (fs::is_directory(filePath))
				directories.emplace_back(filePath);

			else
			{
				cerr << "\nCan't create hash rule for " <<
					filePath.string();

				exit(-1);
			}
		}

		uintmax_t fileSize;
		string action = [&]() noexcept
		{
			if (!updateRules)
			{
				if (static_cast<bool>(secOption))
					return "\nWhitelisting files in ";

				else
					return "\nBlacklisting files in ";
			}

			else
			{
				if (static_cast<bool>(secOption))
					return "\nWhitelisting files and updating rules in ";

				else
					return "\nBlacklisting files and updating rules in ";
			}
		} ();

		if (!regFiles.empty())
		{
			string regFileAction = [&]() noexcept
			{
				if (static_cast<bool>(secOption))
					return "\nWhitelisting ";

				else
					return "\nBlacklisting ";
			} ();

			creatingSingleRule = true;
			RuleProducer ruleProducer;

			for (auto &file : regFiles)
			{
				fileSize = fs::file_size(file);
				if (fileSize && fs::is_regular_file(file))
				{
					ruleProducer.ProcessFile(file, fileSize);
					cout << regFileAction << file << "...";
				}

				else
				{
					cerr << "\nCan't create hash rule for " <<
						file.string();

					exit(-1);
				}

				ProcessRules();
				if (directories.empty())
				{
					RuleConsumer ruleConsumer(updateRules, tempRuleCreation);
					ruleConsumer.ConsumeRules();
				}
			}
		}

		if (!directories.empty())
		{
			creatingSingleRule = false;

			if (ruleCheck)
			{
				ruleProducers.clear();
				ruleConsumers.clear();
			}

			for (const auto &dir : directories)
			{
				dirItQueue.enqueue(make_pair(dir, fileSize));
				cout << action << dir << "...";
			}

			for (unsigned i = 0; i < initThreadCnt; i++)
			{
				if (i != 0)
					Sleep(5);

				ruleProducers.emplace_back(
					&RuleProducer::ProduceRules,
					RuleProducer());
			}

			ProcessRules();
			for (auto &t : ruleProducers)
				t.join();

			for (auto &t : ruleConsumers)
				t.join();

			cout << '\n';
		}
	}
	catch (const fs::filesystem_error &e)
	{
		cerr << '\n' << e.what();
	}
	catch (const exception &e)
	{
		cerr << '\n' << e.what();
	}
}

void SecPolicy::DefaultPolicy()
{
	justListing = false;
	creatingDefaultPolicy = true;

	CreatePolicy({ R"(c:\windows)" }, SecOption::WHITELIST);
}

//create a whitelisting rule, execute the file passed in, and delete the rule
void SecPolicy::TempRun(const string &path)
{
	try
	{
		justListing = false;
		tempRuleCreation = true;
		auto file = fs::path(path);
		file.make_preferred();

		const auto size = fs::file_size(file);
		if (size > 0)
		{
			//create temporary hash rule
			HashRule tempRule(updateRules, tempRuleCreation);
			auto tempRuleData = make_shared<RuleData>(RuleData());
			get<SEC_OPTION>(*tempRuleData) = SecOption::WHITELIST;
			get<RULE_TYPE>(*tempRuleData) = ruleType;
			get<FILE_LOCATION>(*tempRuleData) = file.string();
			get<ITEM_SIZE>(*tempRuleData) = size;

			RuleFindResult result = dataFileMan.FindRule(
				SecOption::BLACKLIST, ruleType, file.string(), *tempRuleData);

			if (result == RuleFindResult::NO_MATCH)
			{
				createdRules++;
				tempRule.CreateNewHashRule(tempRuleData);
				ApplyChanges(false);
			}

			else if (result == RuleFindResult::EXACT_MATCH)
			{
				switchedRules++;
				tempRule.SwitchRule(size, tempRuleData);
				ApplyChanges(false);
			}

			if (result == RuleFindResult::DIFF_SEC_OP)
			{
				skippedRules++;
				cout << '\n' << file.string() << " is already allowed";
			}

			else
				cout << "\nTemporarily allowed " << file.string();

			cout << ". Executing file now...\n";

			//start the program up
			STARTUPINFO si;
			PROCESS_INFORMATION pi;

			SecureZeroMemory(&si, sizeof(si));
			SecureZeroMemory(&pi, sizeof(pi));

			si.cb = sizeof(si);
			bool procCreated = CreateProcess(
				(char*)file.string().c_str(),
				nullptr,
				nullptr,
				nullptr,
				FALSE,
				NULL,
				nullptr,
				(char*)file.parent_path().string().c_str(),
				&si,
				&pi);

			if (!procCreated)
			{
				cerr << "\nCreateProcess error: " << GetLastError() << '\n';
			}

			Sleep(500);
			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);

			if (result == RuleFindResult::NO_MATCH)
			{
				removedRules++;
				tempRule.RemoveRule(get<RULE_GUID>(*tempRuleData),
					SecOption::WHITELIST);
				cout << "\nTemporary rule deleted\n";
			}

			else if (result == RuleFindResult::EXACT_MATCH)
			{
				switchedRules++;
				get<SEC_OPTION>(*tempRuleData) = SecOption::WHITELIST;
				tempRule.SwitchRule(size, tempRuleData);
				cout << "\nRule switched back to deny mode\n";
			}
		}
		else
		{
			cout << "\nCan't create hash rule for " <<
				file.string();
			exit(-1);
		}
	}
	catch (const fs::filesystem_error &e)
	{
		cerr << '\n' << e.what();
	}
	catch (const exception &e)
	{
		cerr << '\n' << e.what();
	}
}

//overload that temporaily whitelists 'dir', and executes 'file'
void SecPolicy::TempRun(const string &dir, const string &file)
{
	try
	{
		justListing = false;
		auto tempDir = fs::path(dir);
		auto exeFile = fs::path(file);

		tempDir.make_preferred();
		exeFile.make_preferred();

		tempRuleCreation = true;
		CreatePolicy(vector<string>{dir}, SecOption::WHITELIST);

		ApplyChanges(false);

		cout << "\nExecuting " << exeFile.string() << " now...\n";

		// start the program up
		STARTUPINFO si;
		PROCESS_INFORMATION pi;

		SecureZeroMemory(&si, sizeof(si));
		SecureZeroMemory(&pi, sizeof(pi));

		si.cb = sizeof(si);
		bool procCreated = CreateProcess(
			(char*)exeFile.string().c_str(),
			nullptr,
			nullptr,
			nullptr,
			FALSE,
			NULL,
			nullptr,
			(char*)exeFile.parent_path().string().c_str(),
			&si,
			&pi);

		if (!procCreated)
			cerr << "\nCreateProcess error: " << GetLastError() << '\n';

		Sleep(500);
		// Close process and thread handles. 
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);

		cout << "\nReverting temporary changes...";

		//delete temporary rules in parallel
		for (const auto &tempRuleID : createdRulesData)
			ruleQueue.enqueue(make_tuple(
				ModificationType::REMOVED, 0ULL, tempRuleID));

		for (const auto &tempRule : updatedRulesData)
			ruleQueue.enqueue(make_tuple(
				ModificationType::SWITCHED, 0ULL, tempRule));

		ruleConsumers.clear();

		if (createdRules)
		{
			for (unsigned i = 0; i < initThreadCnt; i++)
				ruleConsumers.emplace_back(
					&RuleConsumer::RemoveRules,
					RuleConsumer(updateRules, tempRuleCreation));
		}

		if (switchedRules)
		{
			for (unsigned i = 0; i < initThreadCnt; i++)
				ruleConsumers.emplace_back(
					&RuleConsumer::ConsumeRules,
					RuleConsumer(updateRules, tempRuleCreation));
		}

		for (auto &t : ruleConsumers)
			t.join();

		cout << "done" << '\n';

		//clear temp rules
		createdRulesData.clear();
		updatedRulesData.clear();
	}
	catch (const fs::filesystem_error &e)
	{
		cerr << '\n' << e.what();
	}
	catch (const exception &e)
	{
		cerr << '\n' << e.what();
	}
}

//Updates created rules if files they are based off of have changed
void SecPolicy::UpdateRules(const vector<string> &paths)
{
	justListing = false;

	vector<RuleData> temp;
	vector<RuleData> rulesToUpdate;

	for (const auto &path : paths)
	{
		enteredRules.emplace_back(
			secOption, ruleType, path);

		temp = dataFileMan.FindRulesInDir(path);
		rulesToUpdate.insert(rulesToUpdate.begin(), temp.begin(), temp.end());

		cout << "\nUpdating rules in " << path << "...";
	}

	if (!rulesToUpdate.empty())
	{
		for (const auto &rule : rulesToUpdate)
		{
			ruleQueue.enqueue(make_tuple(
				ModificationType::UPDATED,
				fs::file_size(get<FILE_LOCATION>(rule)),
				make_shared<RuleData>(rule)));
		}

		fileCheckingNotDone = false;
		for (unsigned i = 0; i < initThreadCnt; i++)
		{
			ruleConsumers.emplace_back(
				&RuleConsumer::ConsumeRules,
				RuleConsumer(updateRules, tempRuleCreation));
		}

		for (auto &t : ruleConsumers)
			t.join();
	}

	else
		cout << "\nNo rules created in files/dirs specified";

	cout << '\n';
}

//delete the rules the user specifies from registry
void SecPolicy::RemoveRules(vector<string> &paths)
{
	ruleRemoval = true;
	justListing = false;
	
	for (auto &path : paths)
		enteredRules.emplace_back(
			SecOption::REMOVED, ruleType, path);

	for (const auto &file : paths)
	{
		if (fs::is_directory(file))
		{
			cout << "\nRemoving rules of " << file << "...";

			auto rulesInDir = dataFileMan.FindRulesInDir(file);

			if (!rulesInDir.empty())
			{
				for (const auto &rule : rulesInDir)
					removeQueue.enqueue(make_pair(
						get<RULE_GUID>(rule), get<SEC_OPTION>(rule)));
			}

			else
				cerr << "\nCannot remove rules: no rules exist in " << file;
		}

		else if (fs::is_regular_file(file))
		{
			RuleData ruleData;
			if (auto result = dataFileMan.FindRule(secOption, ruleType, file, ruleData);
				result != RuleFindResult::NO_MATCH && result != RuleFindResult::REMOVED)
			{
				cout << "\nRemoving rule for " << file << "...";

				removeQueue.enqueue(make_pair(
					get<FILE_LOCATION>(ruleData), get<SEC_OPTION>(ruleData)));
			}

			else
				cerr << "\nCannot remove rule: no rule for " << file << " exists";
		}
	}

	for (unsigned i = 0; i < initThreadCnt; i++)
		ruleConsumers.emplace_back(
			&RuleConsumer::RemoveRules,
			RuleConsumer(updateRules, tempRuleCreation));

	for (auto &t : ruleConsumers)
		t.join();

	cout << '\n';
}

//Verifies and if nessesary fixes rules in registry
void SecPolicy::CheckRules()
{
	using namespace winreg;

	ruleCheck = true;
	justListing = false;

	if (dataFileMan.AreRulesCreated())
	{
		cout << "\nCannot check rules, no rules have been created\n";
		return;
	}

	auto rules = dataFileMan.GetRuleInfo();

	for (auto &rule : rules)
		ruleStringQueue.enqueue(move(rule));

	for (unsigned i = 0; i < initThreadCnt / 2; i++)
	{
		ruleProducers.emplace_back(
			&RuleProducer::ConvertRules,
			RuleProducer());
	}

	for (unsigned i = 0; i < initThreadCnt / 2; i++)
	{
		ruleConsumers.emplace_back(
			&RuleConsumer::CheckRules,
			RuleConsumer(updateRules, tempRuleCreation));
	}

	RegKey blockKeys(
		HKEY_LOCAL_MACHINE,
		R"(SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Hashes)",
		KEY_READ | KEY_WRITE);

	RegKey allowKeys(
		HKEY_LOCAL_MACHINE,
		R"(SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\262144\Hashes)",
		KEY_READ | KEY_WRITE);

	auto registryBlockRules = blockKeys.EnumSubKeys();
	auto registryAllowRules = allowKeys.EnumSubKeys();

	sort(registryBlockRules.begin(), registryBlockRules.end());
	sort(registryAllowRules.begin(), registryAllowRules.end());

	constexpr char blackList = static_cast<char>(SecOption::BLACKLIST) + '0';
	vector<string> userCreatedRules = dataFileMan.GetRuleInfo();
	auto pivotPnt = partition_point(userCreatedRules.begin(), userCreatedRules.end(), [=](const string &str)
	{
		return str[SEC_OPTION] == blackList;
	});

	for (auto &rule : userCreatedRules)
	{
		const auto guidBegin = rule.find("|{") + 1;
		rule = rule.substr(guidBegin, rule.find("}|") - guidBegin + 1);
	}

	sort(userCreatedRules.begin(), pivotPnt);
	sort(pivotPnt, userCreatedRules.end());

	vector<string> illegalAllowRules;
	vector<string> illegalBlockRules;

	set_difference(
		registryBlockRules.begin(),
		registryBlockRules.end(),
		userCreatedRules.begin(),
		pivotPnt,
		back_inserter(illegalBlockRules));

	set_difference(
		registryAllowRules.begin(),
		registryAllowRules.end(),
		pivotPnt,
		userCreatedRules.end(),
		back_inserter(illegalAllowRules));

	if (!illegalBlockRules.empty())
	{
		for (const auto &rule : illegalBlockRules)
			removeQueue.enqueue(make_pair(rule, SecOption::BLACKLIST));
	}

	if (!illegalAllowRules.empty())
	{
		for (const auto &rule : illegalAllowRules)
			removeQueue.enqueue(make_pair(rule, SecOption::WHITELIST));
	}

	for (auto &t : ruleProducers)
		t.join();

	for (auto &t : ruleConsumers)
		t.join();

	if (!illegalBlockRules.empty() || !illegalAllowRules.empty())
	{
		RuleConsumer ruleConsumer(updateRules, tempRuleCreation);
		ruleConsumer.RemoveRules();
	}

	if (updatedRules == 0 && createdRules == 0 && removedRules == 0)
		cout << "\nFinished checking rules. All rules are correct\n";

	else
		cout << "\n\nFinished checking rules. Changed rules are now corrected\n";
}

//displays created rules
void SecPolicy::ListRules() const
{
	dataFileMan.ListRules(listAllRules);
}

void SecPolicy::ChangePassword()
{
	dataFileMan.SetNewPassword(string{});
}

//makes sure all the nessesary settings are in place to apply a SRP policy,
//if a computer has never had policy applied before it will be missing
//some of these settings. Also check if values in registry are what they should be
void SecPolicy::CheckGlobalSettings()
{
	using namespace winreg;
	try
	{
		RegKey policySettings(
			HKEY_LOCAL_MACHINE,
			R"(SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers)",
			KEY_READ | KEY_WRITE);

		string globalSettings = dataFileMan.GetGlobalSettings();
		string exetensions = globalSettings.substr(globalSettings.find_last_of('|') + 1,
			globalSettings.length());

		string type;
		istringstream iss(exetensions);

		while (getline(iss, type, ','))
			executableTypes.emplace_back(type);

		if (globalSettings != dataFileMan.GetCurrentPolicySettings())
		{
			cout << "\nProceed with caution! Unauthorized changes have been made "
				<< "to the global policy settings."
				<< "\nCorrect settings were reapplied.\n";

			policySettings.SetDwordValue("AuthenticodeEnabled",
				static_cast<DWORD>(globalSettings[AUTHENTICODE_ENABLED] - '0'));

			int defaultLevel = static_cast<DWORD>(globalSettings[DEFAULT_LEVEL] - '0');
			
			if (defaultLevel == 1)
				defaultLevel = 262144;

			policySettings.SetDwordValue("DefaultLevel", defaultLevel);

			policySettings.SetMultiStringValue("ExecutableTypes", executableTypes);

			policySettings.SetDwordValue("PolicyScope",
				static_cast<DWORD>(globalSettings[POLCIY_SCOPE] - '0'));

			policySettings.SetDwordValue("TransparentEnabled",
				static_cast<DWORD>(globalSettings[TRANSPARENT_ENABLED] - '0'));
		}

		auto exePath = [=]()
		{
			auto temp = fs::current_path().string() + '\\' + programName;
			for (auto &letter : temp)
				letter = std::move(tolower(letter));

			return temp;
		} ();

		if (!dataFileMan.FindBASPRule(exePath))
		{
			RuleData ruleData;

			cout << "\nBASP isn't explicitly allowed, whitelisting now...";

			auto tempPath = fs::temp_directory_path().string() + '\\'  + programName;
			
			fs::copy_file(exePath, tempPath);
			get<SEC_OPTION>(ruleData) = SecOption::WHITELIST;
			get<FILE_LOCATION>(ruleData) = tempPath;
			get<ITEM_SIZE>(ruleData) = fs::file_size(tempPath);
			get<IS_BASP_BINARY>(ruleData) = true;
			baspRule = make_shared<RuleData>(ruleData);

			HashRule hashRule(false, false);
			hashRule.CreateNewHashRule(baspRule);

			get<FILE_LOCATION>(*baspRule) = exePath;
			fs::remove(tempPath);

			cout << "done\n";

			whitelistedBASP = true;
			ApplyChanges(false);
			createdRules++;
		}
	}
	catch (const RegException &e)
	{
		cerr << '\n' << e.what() << ". Error code " << e.ErrorCode();
	}
	catch (const fs::filesystem_error &e)
	{
		cerr << '\n' << e.what();
	}
	catch (const exception &e)
	{
		cerr << '\n' << e.what();
	}
}

//verifies files sent from RuleProducers are valid and if so starts proccessing them
void SecPolicy::ProcessRules()
{
	try
	{
		bool filesLeft;
		string filePath;
		string filename;
		FileInfo fileInfo;
		string extension;
		RuleData ruleData;
		uintmax_t fileSize;
		ConsumerToken ruleCtok(fileCheckQueue);

		do
		{
			filesLeft = doneProducers.load(memory_order_acquire) != producerCount;
			while (fileCheckQueue.try_dequeue(ruleCtok, fileInfo))
			{
				filesLeft = true;
				filePath = move(get<RULE_PATH>(fileInfo));
				filename = move(get<FILENAME>(fileInfo));
				extension = move(get<EXTENSION>(fileInfo));
				fileSize = get<DATA_SIZE>(fileInfo);

				//check if the file is of one of the executable types 
				if (binary_search(executableTypes.cbegin(),
					executableTypes.cend(), extension))
				{
					const RuleFindResult result = dataFileMan.FindRule(
						secOption, ruleType, filePath, ruleData);

					if (result == RuleFindResult::NO_MATCH)
					{
						if (creatingDefaultPolicy && binary_search(
							bypassFiles.cbegin(), bypassFiles.cend(), filename))
						{
							enteredRules.emplace_back(SecOption::BLACKLIST, ruleType, filePath);
							get<SEC_OPTION>(ruleData) = SecOption::BLACKLIST;
						}

						else
							get<SEC_OPTION>(ruleData) = secOption;

						get<FILE_LOCATION>(ruleData) = filePath;
						get<ITEM_SIZE>(ruleData) = fileSize;
						get<IS_BASP_BINARY>(ruleData) = false;
						createdRulesData.emplace_back(make_shared<RuleData>(ruleData));

						ruleQueue.enqueue(
							make_tuple(
								ModificationType::CREATED, 0ULL, createdRulesData.back()));
					}
					else if (result == RuleFindResult::DIFF_SEC_OP)
					{
						updatedRulesData.emplace_back(make_shared<RuleData>(ruleData));

						ruleQueue.enqueue(
							make_tuple(
								ModificationType::SWITCHED, fileSize, updatedRulesData.back()));
					}
					else if (result == RuleFindResult::EXACT_MATCH)
					{
						updatedRulesData.emplace_back(make_shared<RuleData>(ruleData));

						if (updateRules)
						{
							ruleQueue.enqueue(
								make_tuple(
									ModificationType::UPDATED, fileSize, updatedRulesData.back()));
						}

						else
							skippedRules++;
					}

					if (!creatingSingleRule && (ruleConsumers.size() < initThreadCnt
						|| ruleConsumers.size() < initThreadCnt + doneProducers))
						ruleConsumers.emplace_back(
							&RuleConsumer::ConsumeRules,
							RuleConsumer(updateRules, tempRuleCreation));
				}
			}
		} while (filesLeft);

		fileCheckingNotDone = false;
	}
	catch (const fs::filesystem_error &e)
	{
		cout << e.what() << '\n';
	}
	catch (const exception &e)
	{
		cout << e.what() << '\n';
	}
}

//print how many rules were created and runtime of rule creation
void SecPolicy::PrintStats(const TimeDiff diff) const
{
	using namespace chrono;

	int secs;
	const int mins = duration<double, milli>(diff).count() / 60000;

	if (mins > 0)
		secs = static_cast<int>(
			duration<double, milli>(diff).count() / 1000) % (mins * 60);

	else
		secs = duration<double, milli>(diff).count() / 1000;

	cout << "\nCreated  " << createdRules << " rules,\n"
		<< "Switched " << switchedRules << " rules,\n"
		<< "Updated  " << updatedRules << " rules,\n"
		<< "Skipped  " << skippedRules << " rules, and\n"
		<< "Removed  " << removedRules << " rules "
		<< "in ";

	if (mins > 0)
		cout << mins << " mins, " << secs << " secs" << '\n';

	else
		cout << secs << " secs" << '\n';
}

//make sure Windows applies policy changes
void SecPolicy::ApplyChanges(bool updateSettings)
{
	//Windows randomly applies the rules that are written to the registry,
	//so to persuade Windows to apply the rule changes we have to change a 
	//global policy setting. A random executeable type is added and then removed 
	//so that it doesn't really affect anything. Changing any other of the global
	//rules even for a split second, is a security risk.
	using namespace winreg;

	try
	{
		cout << "\nApplying changes...";

		executableTypes.emplace_back("ABC");
		RegKey policySettings(
			HKEY_LOCAL_MACHINE,
			"SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers",
			KEY_READ | KEY_WRITE);

		policySettings.SetMultiStringValue("ExecutableTypes", executableTypes);
		
		Sleep(500);

		executableTypes.pop_back();
		policySettings.SetMultiStringValue("ExecutableTypes", executableTypes);

		policySettings.Close();

		//write changes to settings file
		if (updateSettings && !tempRuleCreation)
		{
			dataFileMan.UpdateUserRules(enteredRules, ruleRemoval);

			if (whitelistedBASP)
				dataFileMan.AddBASPRule(*baspRule);

			if (createdRules)
				dataFileMan.InsertNewEntries(createdRulesData);

			if (updatedRules || switchedRules)
				dataFileMan.UpdateEntries(secOption, updatedRulesData);

			//if a directory that has already had rules created for it is proccessed again,
			//check if any files have been removed
			if ((updatedRules || skippedRules) && !ruleCheck)
			{
				auto totalRulesProcessed = 
					[](const vector<RuleDataPtr> &vec1, const vector<RuleDataPtr> &vec2)
					{
						vector<RuleData> processedRules;
						for (const auto& rule : vec1)
							processedRules.emplace_back(*rule);

						for (const auto& rule : vec2)
							processedRules.emplace_back(*rule);

						return processedRules;
					};

				auto deletedFiles = dataFileMan.GetDeletedFiles(
					totalRulesProcessed(createdRulesData, updatedRulesData));

				if (!deletedFiles.empty())
				{
					ruleConsumers.clear();
					for (const auto &rule : deletedFiles)
						removeQueue.enqueue(make_pair(
							get<RULE_GUID>(rule), get<SEC_OPTION>(rule)));

					RuleConsumer ruleConsumer(updateRules, tempRuleCreation);
					ruleConsumer.RemoveRules();

					dataFileMan.RemoveDeletedFiles(deletedFiles);
				}
			}

			if (removedRules)
				dataFileMan.RemoveOldEntries();

			dataFileMan.WriteChanges();
		}

		cout << "done\n";
	}
	catch (const RegException &e)
	{
		cerr << '\n' << e.what() << ". Error code " << e.ErrorCode();
	}
	catch (const exception &e)
	{
		cerr << e.what() << '\n';
	}
}