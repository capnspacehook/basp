#include "AppSecPolicy.hpp"
#include "Windows.h"
#include "WinReg.hpp"

#include <string>
#include <vector>
#pragma once

class HashRule
{
public:
	explicit HashRule() noexcept = default;
	explicit HashRule(const HashRule &rhs) noexcept
	{
		guid = rhs.guid;
		description = rhs.description;
		fileVersion = rhs.fileVersion;
		friendlyName = rhs.friendlyName;
		itemData = rhs.itemData;
		itemSize = rhs.itemSize;
		lastModified = rhs.lastModified;
		sha256Hash = rhs.sha256Hash;
	}
	explicit HashRule(HashRule &&rhs) noexcept
	{
		guid = rhs.guid;
		description = rhs.description;
		fileVersion = rhs.fileVersion;
		friendlyName = rhs.friendlyName;
		itemData = rhs.itemData;
		itemSize = rhs.itemSize;
		lastModified = rhs.lastModified;
		sha256Hash = rhs.sha256Hash;
	}
	void CreateNewHashRule(const std::string &fileName,
		const AppSecPolicy::SecOptions &policy,
		const long long& fileSize, std::string *subKey);
	void RemoveRule(const std::string *guid,
		const AppSecPolicy::SecOptions &policy);
	
private:
	void EnumFileVersion(const std::string &fileName);
	void EnumFriendlyName(const std::string &fileName);
	inline void EnumFileTime();
	void HashDigests(const std::string &fileName);
	inline void CreateGUID();
	void WriteToRegistry(const std::string &fileName,
		const AppSecPolicy::SecOptions &policy);
	inline bool MakeGUID();
	inline std::vector<BYTE> convertStrToByte(std::string &str) noexcept;

	std::string guid;
	static const std::string fileProps[5];
	std::string description = "";
	std::string fileVersion;
	std::string friendlyName = "";
	static const int hashAlg = 32771;
	std::vector<BYTE> itemData;
	long long itemSize;
	long long lastModified;
	static const int shaHashAlg = 32780;
	std::vector<BYTE> sha256Hash;
};