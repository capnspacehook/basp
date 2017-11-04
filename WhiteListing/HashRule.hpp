#include "AppSecPolicy.hpp"
#include "Windows.h"
#include "WinReg.hpp"

#include <string>
#include <vector>
#pragma once

class HashRule
{
public:
	HashRule() {}
	HashRule(const std::string &fileName, 
		const AppSecPolicy::SecOptions &secOption)
	{
		CreateNewHashRule(fileName, secOption);
	}
	void CreateNewHashRule(std::string fileName, AppSecPolicy::SecOptions policy);
	void EnumFileVersion(std::string fileName);
	void EnumFriendlyName(std::string fileName);
	void EnumItemSize(std::string fileName);
	void EnumFileTime();
	void HashDigests(std::string fileName);
	void CreateGUID();
	void WriteToRegistry(AppSecPolicy::SecOptions policy) noexcept;
	
private:
	bool MakeGUID();
	inline std::vector<BYTE> convertStrToByte(std::string str) noexcept;

	std::string guid;
	std::string fileProps[5] = {
		"OriginalFilename",
		"InternalName",
		"FileDescription",
		"ProductName",
		"CompanyName" };
	std::string description = "";
	std::string fileVersion;
	std::string friendlyName = "";
	int hashAlg = 32771;
	std::vector<BYTE> itemData;
	long long itemSize;
	long long lastModified;
	int saferFlags = 0;
	int shaHashAlg = 32780;
	std::vector<BYTE> sha256Hash;
};