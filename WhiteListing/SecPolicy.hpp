#include "AppSecPolicy.hpp"
#include "Windows.h"
#include "WinReg.hpp"

#include <system_error>
#include <filesystem>
#include <iostream>
#include <chrono>
#include <thread>
#include <string>
#include <vector>
#pragma once

namespace fs = std::experimental::filesystem;

class SecPolicy
{
public:
	SecPolicy() {}
	~SecPolicy()
	{
		//wait for all threads to finish
		for (auto &t : threads)
			t.join();

		std::common_type_t<std::chrono::nanoseconds, 
			std::chrono::nanoseconds> diff =
			std::chrono::high_resolution_clock::now() - startTime;

		int secs;
		int mins = std::chrono::duration<double, std::milli>(diff).count() / 60000;
		if (mins > 0)
			secs = (int)(std::chrono::duration<double, std::milli>(diff).count() / 1000) % (mins * 60);
		else
			secs = std::chrono::duration<double, std::milli>(diff).count() / 1000;

		if (tempRuleCreation)
		{
			std::cout << "Created and removed " << ruleCount
				<< " temporary hash rules in " << mins << " mins, "
				<< secs << " secs " << std::endl;
		}
		else
		{
			std::cout << "Created " << ruleCount << " hash rules in "
				<< mins << " mins, " << secs << " secs" << std::endl;
		}
	}
	void CreatePolicy(const std::string &path,
		const AppSecPolicy::SecOptions &op) noexcept;
	void CreatePolicy(const std::vector<std::string> &paths,
		const AppSecPolicy::SecOptions & op) noexcept;
	void TempRun(const std::string &path) noexcept;
	void TempRun(const std::string &dir, const std::string &exeFile) noexcept;

	void EnumExeTypes() noexcept;
	void EnumAttributes(const std::string&) noexcept;
	void EnumDirContents(const fs::path&, long long&) noexcept;
	void CheckValidType(const fs::path&, const long long&) noexcept;
private:
	int ruleCount = 0;
	bool tempRuleCreation = false;
	std::vector<std::thread> threads;
	AppSecPolicy::SecOptions secOption;
	//stores the GUIDs that are created for temporary hash rules
	//for easy deletion
	std::vector<std::string*> GUIDs;
	std::vector<std::string> executableTypes = {
		"ADE", "ADP", "BAS", "BAT", "BGI", "CHM", "CMD", "COM", "CPL", "CRT",
		"DIAGCAB", "DLL", "EXE", "HLP", "HTA", "INF", "INS", "ISP", "JS", 
		"JSE", "LNK", "MDB", "MDE", "MSC", "MSI", "MSP", "MST", "OCX", "PCD",
		"PIF", "PS1", "PS2", "PSM", "REG", "SCR", "SCT", "SHS", "URL", "VB", 
		"VBE", "VBS", "VBSCRIPT", "WSC", "XAML", "XBAP", "XPI" };
	std::chrono::time_point<std::chrono::steady_clock> startTime =
		std::chrono::high_resolution_clock::now();
};