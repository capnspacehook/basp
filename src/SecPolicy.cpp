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
#include <memory>

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
ConcurrentQueue<RuleData> SecPolicy::ruleCheckQueue;
ConcurrentQueue<string> SecPolicy::ruleStringQueue;

//creates hash rules for each of the files in the vector 'paths'
void SecPolicy::CreatePolicy(const vector<string> &paths, const SecOption &op,
	RuleType rType)
{
	justListing = false;
	secOption = op;
	ruleType = rType;

	for (const auto &path : paths)
	{
		enteredRules.emplace_back(
			secOption, ruleType, path);
	}

	StartProcessing(paths);
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
			HashRule tempRule;
			auto tempRuleData = make_shared<RuleData>(RuleData());
			get<SEC_OPTION>(*tempRuleData) = SecOption::WHITELIST;
			get<RULE_TYPE>(*tempRuleData) = ruleType;
			get<FILE_LOCATION>(*tempRuleData) = file.string();

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
				cout << file.string() << " is already allowed.";
			}

			else
				cout << "Temporarily allowed " << file.string();

			cout << ". Executing file now...\n\n";

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
				cerr << "CreateProcess error: " << GetLastError() << '\n';
			}

			Sleep(1000);
			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);

			if (result == RuleFindResult::NO_MATCH)
			{
				removedRules++;
				tempRule.RemoveRule(get<RULE_GUID>(*tempRuleData),
					SecOption::WHITELIST);
				cout << "Temporary rule deleted\n";
			}

			else if (result == RuleFindResult::EXACT_MATCH)
			{
				switchedRules++;
				get<SEC_OPTION>(*tempRuleData) = SecOption::WHITELIST;
				tempRule.SwitchRule(size, tempRuleData);
				cout << "Rule switched back to deny mode.\n";
			}
		}
		else
		{
			cout << "Can't create hash rule for " <<
				file.string() << '\n';
			exit(-1);
		}
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

		cout << ". Executing " << exeFile.string() << " now...\n\n";

		// start the program up
		STARTUPINFO si;
		PROCESS_INFORMATION pi;

		SecureZeroMemory(&si, sizeof(si));
		SecureZeroMemory(&pi, sizeof(pi));

		si.cb = sizeof(si);
		bool procCreated = CreateProcess(
			exeFile.string().c_str(),
			nullptr,
			nullptr,
			nullptr,
			FALSE,
			NULL,
			nullptr,
			exeFile.parent_path().string().c_str(),
			&si,
			&pi);

		if (!procCreated)
		{
			cerr << "CreateProcess error: " << GetLastError() << '\n';
			return;
		}

		Sleep(1000);
		// Close process and thread handles. 
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);

		cout << "Reverting temporary changes...";

		//delete temporary rules in parallel
		for (const auto &tempRuleID : createdRulesData)
			ruleQueue.enqueue(make_tuple(
				ModificationType::REMOVED, 0ULL, tempRuleID));

		for (const auto &tempRule : updatedRulesData)
			ruleQueue.enqueue(make_tuple(
				ModificationType::SWITCHED, 0ULL, tempRule));

		ruleConsumers.clear();
		for (int i = 0; i < maxThreads; i++)
			ruleConsumers.emplace_back(
				&RuleConsumer::ConsumeRules,
				RuleConsumer());

		for (auto &t : ruleConsumers)
			t.join();

		cout << "done" << '\n';

		//clear temp rules
		createdRulesData.clear();
		updatedRulesData.clear();
	}
	catch (const fs::filesystem_error &e)
	{
		cerr << e.what() << '\n';
	}
	catch (const exception &e)
	{
		cerr << e.what() << '\n';
	}
}

//delete rules from registry
void SecPolicy::RemoveRules(vector<string> &paths)
{
	ruleRemoval = true;
	justListing = false;
	
	for (auto &path : paths)
		enteredRules.emplace_back(
			SecOption::REMOVED, ruleType, path);

	DeleteRules(paths);
}

void SecPolicy::CheckRules()
{
	using namespace winreg;

	ruleCheck = true;
	justListing = false;

	if (dataFileMan.AreRulesCreated())
	{
		cout << "Cannot check rules, no rules have been created\n";
		return;
	}

	string temp;
	istringstream ruleStrings(dataFileMan.GetRuleList());

	getline(ruleStrings, temp);
	getline(ruleStrings, temp);
	getline(ruleStrings, temp);

	while (temp.back() == '*')
		getline(ruleStrings, temp);

	ruleStringQueue.enqueue(move(temp));

	while (getline(ruleStrings, temp))
		ruleStringQueue.enqueue(move(temp));
	
	/*RegKey policyKey(
		HKEY_LOCAL_MACHINE,
		"SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers",
		KEY_READ | KEY_WRITE);*/

	for (int i = 0; i < initThreadCnt; i++)
	{
		ruleProducers.emplace_back(
			&RuleProducer::ConvertRules,
			RuleProducer());
	}

	for (int i = 0; i < initThreadCnt; i++)
	{
		ruleConsumers.emplace_back(
			&RuleConsumer::CheckRules,
			RuleConsumer());
	}

	for (auto &t : ruleProducers)
		t.join();

	for (auto &t : ruleConsumers)
		t.join();

	if (updatedRules == 0 && createdRules == 0)
		cout << "\nFinished checking rules. All rules are correct";

	else
		cout << "\nFinished checking rules. Changed rules are now corrected";
}

void SecPolicy::ListRules() const
{
	dataFileMan.ListRules(listAllRules);
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
			"SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers",
			KEY_READ | KEY_WRITE);

		string globalSettings = dataFileMan.GetGlobalSettings();
		string exetensions = globalSettings.substr(globalSettings.find_last_of('|') + 1,
			globalSettings.length());

		string type;
		istringstream iss(exetensions);

		while (getline(iss, type, ','))
			executableTypes.emplace_back(type);

		vector<pair<string, DWORD>> keys = policySettings.EnumValues();

		if (keys.size() < 5)
		{
			policySettings.SetDwordValue("AuthenticodeEnabled", 0);
			policySettings.SetDwordValue("DefaultLevel", 262144);
			policySettings.SetMultiStringValue("ExecutableTypes", executableTypes);
			policySettings.SetDwordValue("PolicyScope", 0);
			policySettings.SetDwordValue("TransparentEnabled", 1);
		}

		if (globalSettings != dataFileMan.GetCurrentPolicySettings())
		{
			cout << "Proceed with caution! Unauthorized changes have been made "
				<< "to the global policy settings.\n"
				<< "Correct settings were reapplied.\n";

			policySettings.SetDwordValue("AuthenticodeEnabled",
				static_cast<int>(globalSettings[AUTHENTICODE_ENABLED] - '0'));

			int defaultLevel = static_cast<int>(globalSettings[DEFAULT_LEVEL] - '0');
			
			if (defaultLevel == 1)
				defaultLevel = 262144;

			policySettings.SetDwordValue("DefaultLevel", defaultLevel);

			policySettings.SetMultiStringValue("ExecutableTypes", executableTypes);

			policySettings.SetDwordValue("PolicyScope",
				static_cast<int>(globalSettings[POLCIY_SCOPE] - '0'));

			policySettings.SetDwordValue("TransparentEnabled",
				static_cast<int>(globalSettings[TRANSPARENT_ENABLED] - '0'));
		}
	}
	catch (const RegException &e)
	{
		cout << e.what() << '\n';
	}
	catch (const exception &e)
	{
		cout << e.what() << '\n';
	}
}

//detirmine whether file passed is a 
//regular file or directory and process respectively
void SecPolicy::StartProcessing(const vector<string> &files)
{
	try
	{
		vector<fs::path> regFiles;
		vector<fs::path> directories;
		for (const auto &file : files)
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
		string action = [&]()
		{
			if (static_cast<bool>(secOption))
				return "\nWhitelisting";

			else
				return "\nBlacklisting";
		} ();

		if (!regFiles.empty())
		{
			creatingSingleRule = true;
			RuleProducer ruleProducer;
			RuleConsumer ruleConsumer;

			for (auto &file : regFiles)
			{
				fileSize = fs::file_size(file);
				if (fileSize && fs::is_regular_file(file))
				{
					ruleProducer.ProcessFile(file, fileSize);
					cout << action << ' ' << file << "...";
				}

				else
				{
					cerr << "\nCan't create hash rule for " <<
						file.string();

					exit(-1);
				}

				ModifyRules();
				if (directories.empty())
					ruleConsumer.ConsumeRules();
			}
		}

		if (!directories.empty())
		{
			creatingSingleRule = false;

			for (const auto &dir : directories)
			{
				dirItQueue.enqueue(make_pair(dir, fileSize));
				cout << action << " files in " << dir << "...";
			}

			for (int i = 0; i < initThreadCnt; i++)
			{
				if (i != 0)
					Sleep(5);

				ruleProducers.emplace_back(
					&RuleProducer::ProduceRules,
					RuleProducer());
			}

			ModifyRules();
			for (auto &t : ruleProducers)
				t.join();

			for (auto &t : ruleConsumers)
				t.join();

			cout << '\n';
		}
	}
	catch (const fs::filesystem_error &e)
	{
		cerr << e.what() << '\n';
	}
	catch (const exception &e)
	{
		cerr << e.what() << '\n';
	}
}

//checks whether file is a valid type as detirmined by the list 
//in the member variable executableTypes and if it is, start creating
//a new hash rule for the file in a new thread
void SecPolicy::ModifyRules()
{
	try
	{
		string file;
		bool filesLeft;
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
				file = move(get<RULE_PATH>(fileInfo));
				extension = move(get<EXTENSION>(fileInfo));
				fileSize = get<DATA_SIZE>(fileInfo);

				//check if the file is of one of the executable types 
				if (binary_search(executableTypes.cbegin(),
					executableTypes.cend(), extension))
				{
					const RuleFindResult result = dataFileMan.FindRule(
						secOption, ruleType, file, ruleData);

					if (result == RuleFindResult::NO_MATCH)
					{
						get<SEC_OPTION>(ruleData) = secOption;
						get<FILE_LOCATION>(ruleData) = file;
						get<ITEM_SIZE>(ruleData) = fileSize;
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
							RuleConsumer());
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

void SecPolicy::DeleteRules(const vector<string> &files)
{
	for (const auto &file : files)
	{
		if (fs::is_directory(file))
		{
			cout << "\nRemoving rules of " << file << "...";

			auto rulesInDir = dataFileMan.FindRulesInDir(file);

			if (!rulesInDir.empty())
			{
				for (const auto &rule : rulesInDir)
					ruleQueue.enqueue(make_tuple(
						ModificationType::REMOVED, 0ULL, make_shared<RuleData>(rule)));
			}

			else
			{
				cerr << "\nCannot remove rules: no rules exist in " << file;
			}
		}

		else if (fs::is_regular_file(file))
		{
			RuleData ruleData;
			if (dataFileMan.FindRule(secOption, ruleType, file, ruleData)
				!= RuleFindResult::NO_MATCH)
			{
				cout << "\nRemoving rule for " << file << "...";

				ruleQueue.enqueue(make_tuple(
					ModificationType::REMOVED, 0ULL, make_shared<RuleData>(ruleData)));
			}

			else
				cerr << "\nCannot remove rule: no rule for " << file << " exists";
		}
	}

	for (int i = 0; i < initThreadCnt; i++)
		ruleConsumers.emplace_back(
			&RuleConsumer::RemoveRules,
			RuleConsumer());

	for (auto &t : ruleConsumers)
		t.join();

	cout << '\n';
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
		Sleep(1000);

		executableTypes.pop_back();
		policySettings.SetMultiStringValue("ExecutableTypes", executableTypes);

		policySettings.Close();

		//write changes to settings file
		if (updateSettings && !tempRuleCreation)
		{
			dataFileMan.UpdateUserRules(enteredRules, ruleRemoval);

			if (createdRules)
				dataFileMan.InsertNewEntries(createdRulesData);

			if (updatedRules || switchedRules)
				dataFileMan.UpdateEntries(secOption, updatedRulesData);

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
						ruleQueue.enqueue(move(make_tuple(
							ModificationType::REMOVED, 0ULL, make_shared<RuleData>(rule))));

					RuleConsumer ruleConsumer;
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
		cout << e.what() << '\n';
	}
	catch (const exception &e)
	{
		cout << e.what() << '\n';
	}
}