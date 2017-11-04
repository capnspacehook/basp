#include "AppSecPolicy.hpp"
#include "Windows.h"
#include "WinReg.hpp"

#include <system_error>
#include <filesystem>
#include <iostream>
#include <thread>
#include <string>
#include <vector>
#pragma once

namespace fs = std::experimental::filesystem;

class SecPolicy
{
public:
	SecPolicy(std::string path, AppSecPolicy::SecOptions op) noexcept
	{
		filePath = path;
		secOption = op;
		EnumExeTypes();
		EnumAttributes(filePath);
	}
	~SecPolicy()
	{
		for (auto &t : threads)
			t.join();

		std::cout << "Created " << ruleCount << " hash rules" 
			<< std::endl;
	}

	void EnumExeTypes() noexcept;
	void EnumAttributes(const std::string&) noexcept;
	void EnumDirContents(const fs::path&, long long&) noexcept;
	void CheckValidType(const fs::path&, const long long&) noexcept;
private:
	int ruleCount = 0;
	std::string filePath;
	std::vector<std::thread> threads;
	AppSecPolicy::SecOptions secOption;
	std::vector<std::string> executableTypes = {
		"ADE", "ADP", "BAS", "BAT", "BGI", "CHM", "CMD", "COM", "CPL", "CRT",
		"DIAGCAB", "DLL", "EXE", "HLP", "HTA", "INF", "INS", "ISP", "JS", 
		"JSE", "LNK", "MDB", "MDE", "MSC", "MSI", "MSP", "MST", "OCX", "PCD",
		"PIF", "PS1", "PS2", "PSM", "REG", "SCR","SHS", "URL", "VB", 
		"WSC", "XAML", "XBAP", "XPI" };
};