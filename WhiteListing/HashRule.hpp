#include "AppSecPolicy.hpp"
#include "Windows.h"
#include "WinReg.hpp"

#include <string>
#include <vector>
#pragma once

class HashRule
{
public:
	HashRule() {};
	void CreateNewHashRule(const std::string &fileName,
		const AppSecPolicy::SecOptions &policy,
		const long long& fileSize);
	void CreateTempHashRule(const std::string &fileName,
		const AppSecPolicy::SecOptions &policy,
		const long long& fileSize, std::string *subKey);

	void EnumFileVersion(const std::string &fileName);
	void EnumFriendlyName(const std::string &fileName);
	void EnumFileTime();
	void HashDigests(const std::string &fileName);
	inline void CreateGUID();
	void WriteToRegistry(const std::string &fileName, 
		const AppSecPolicy::SecOptions &policy) noexcept;
	void DeleteTempRule(const std::string *guid, 
		const AppSecPolicy::SecOptions &policy) noexcept;
	
private:
	inline bool MakeGUID();
	inline std::vector<BYTE> convertStrToByte(std::string &str) noexcept;

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
	int shaHashAlg = 32780;
	std::vector<BYTE> sha256Hash;
};