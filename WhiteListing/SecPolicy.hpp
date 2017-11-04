#include "AppSecPolicy.hpp"
#include "Windows.h"
#include "WinReg.hpp"

#include <system_error>
#include <filesystem>
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
	}

	void EnumExeTypes() noexcept;
	void EnumAttributes(const std::string&) noexcept;
	void EnumDirContents(const fs::path&, const std::error_code&) noexcept;
	void CheckValidType(const fs::path&) noexcept;
private:
	inline bool FindInStrIC(std::string, std::string) const noexcept;

	std::string filePath;
	std::vector<std::thread> threads;
	AppSecPolicy::SecOptions secOption;
	std::vector<std::string> executableTypes;
};