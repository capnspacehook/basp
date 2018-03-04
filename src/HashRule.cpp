#include "SecPolicy.hpp"
#include "HashRule.hpp"
#include "include\WinReg.hpp"

#include "Strsafe.h"
#include "Rpc.h"

//nessesary for md5 to function 
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include "include\Crypto++\hex.h"
#include "include\Crypto++\files.h"
#include "include\Crypto++\filters.h"
#include "include\Crypto++\md5.h"
#include "include\Crypto++\sha.h"

#include <exception>

#pragma comment(lib, "Version.lib")

using namespace std;
using namespace AppSecPolicy;

//initialize fileProps
const string HashRule::fileProps[5] = {
	"OriginalFilename",
	"InternalName",
	"FileDescription",
	"ProductName",
	"CompanyName" };

//creates new hash rule
void HashRule::CreateNewHashRule(RuleDataPtr &ruleData)
{
	const string_view fileName = get<FILE_LOCATION>(*ruleData);

	//build of nessesary data to create hash rule
	itemSize = get<ITEM_SIZE>(*ruleData);
	EnumFriendlyName(fileName);
	EnumCreationTime();
	HashDigests(fileName);
	CreateGUID();
	WriteToRegistry(fileName, get<SEC_OPTION>(*ruleData));
	
	//assign rule information so the rule can be stored in settings file
	get<RULE_GUID>(*ruleData) = move(guid);
	get<FRIENDLY_NAME>(*ruleData) = move(friendlyName);
	get<ITEM_SIZE>(*ruleData) = itemSize;
	get<LAST_MODIFIED>(*ruleData) = lastModified;
	get<ITEM_DATA>(*ruleData) = move(itemData);
	get<SHA256_HASH>(*ruleData) = move(sha256Hash);

	SecPolicy::createdRules++;
}

void HashRule::SwitchRule(const uintmax_t &fileSize, RuleDataPtr &ruleData)
{
	using namespace winreg;

	try
	{
		const SecOption originalOp = get<SEC_OPTION>(*ruleData);
		SecOption swappedOp = static_cast<SecOption>(!static_cast<bool>(originalOp));

		guid = get<RULE_GUID>(*ruleData);
		get<SEC_OPTION>(*ruleData) = swappedOp;

		if (!CheckIfRuleOutdated(fileSize, ruleData, false))
		{
			string fileName = get<FILE_LOCATION>(*ruleData);
			friendlyName = get<FRIENDLY_NAME>(*ruleData);
			itemSize = get<ITEM_SIZE>(*ruleData);
			itemData = get<ITEM_DATA>(*ruleData);
			sha256Hash = get<SHA256_HASH>(*ruleData);
			EnumCreationTime();

			WriteToRegistry(fileName, swappedOp);
			get<MOD_STATUS>(*ruleData) = ModificationType::SWITCHED;
		}

		//remove old rule
		RemoveRule(guid, originalOp);

		SecPolicy::switchedRules++;
	}
	catch (const exception &e)
	{
		cout << e.what() << endl;
	}
}

void HashRule::RemoveRule(const string &ruleGuid, SecOption policy) const
{
	using namespace winreg;
	
	const string policyPath = [&]() noexcept
	{
		if (policy == SecOption::BLACKLIST)
			return R"(SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Hashes\)";
		else
			return R"(SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\262144\Hashes\)";
	} ();
	
	try
	{
		RegKey tempKey;
		if (!tempKey.Open(HKEY_LOCAL_MACHINE, policyPath, DELETE))
		{
			cout << "\nError removing rule: rule does not exist";
			SecPolicy::skippedRules++;
			return;
		}
	
		tempKey.DeleteKey(ruleGuid + R"(\SHA256)", KEY_WOW64_32KEY);
		tempKey.DeleteKey(ruleGuid, KEY_WOW64_32KEY);

		SecPolicy::removedRules++;
	}
	catch (const RegException &e)
	{
		cout << '\n' << e.what();
	}
	catch (const exception &e)
	{
		cout << '\n' << e.what();
	}
}

bool HashRule::CheckIfRuleOutdated(const uintmax_t &fileSize, 
	RuleDataPtr& ruleData, bool updatingRule)
{
	if (!updateRules)
		return false;

	bool fileHashed = false;
	bool fileChanged = false;
	
	if (fileSize != get<ITEM_SIZE>(*ruleData))
		fileChanged = true;

	else
	{
		HashDigests(get<FILE_LOCATION>(*ruleData));
		if (sha256Hash != get<SHA256_HASH>(*ruleData))
			fileChanged = true;

		fileHashed = true;
	}

	if (fileChanged)
		UpdateRule(fileSize, *ruleData, fileHashed);

	if (!fileChanged && updatingRule)
	{
		SecPolicy::skippedRules++;
		get<MOD_STATUS>(*ruleData) = ModificationType::SKIPPED;
	}

	return fileChanged;
}

void HashRule::UpdateRule(const uintmax_t &fileSize, RuleData &ruleData, bool fileHashed)
{
	itemSize = fileSize;
	guid = get<RULE_GUID>(ruleData);
	EnumFriendlyName(get<FILE_LOCATION>(ruleData));

	if (!fileHashed)
		HashDigests(get<FILE_LOCATION>(ruleData));

	EnumCreationTime();
	WriteToRegistry(get<FILE_LOCATION>(ruleData),
		get<SEC_OPTION>(ruleData));

	get<FRIENDLY_NAME>(ruleData) = move(friendlyName);
	get<ITEM_SIZE>(ruleData) = itemSize;
	get<LAST_MODIFIED>(ruleData) = lastModified;
	get<ITEM_DATA>(ruleData) = move(itemData);
	get<SHA256_HASH>(ruleData) = move(sha256Hash);
	get<MOD_STATUS>(ruleData) = ModificationType::UPDATED;

	SecPolicy::updatedRules++;
}

void HashRule::CheckRuleIntegrity(const RuleData &ruleData)
{
	using namespace winreg;

	try
	{
		bool ruleModified = false;
		bool ruleDeleted = false;
		auto policy = get<SEC_OPTION>(ruleData);
		string policyPath = [&]() noexcept
		{
			if (policy == SecOption::BLACKLIST)
				return R"(SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Hashes\)" + get<RULE_GUID>(ruleData);
			else
				return R"(SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\262144\Hashes\)" + get<RULE_GUID>(ruleData);
		} ();

		RegKey hashRuleKey;
		const string ruleName = get<FILE_LOCATION>(ruleData);

		if (!hashRuleKey.Open(HKEY_LOCAL_MACHINE, policyPath, KEY_READ | KEY_WRITE))
		{
			hashRuleKey.Create(
				HKEY_LOCAL_MACHINE,
				policyPath,
				KEY_READ | KEY_WRITE);

			hashRuleKey.SetStringValue("FriendlyName", get<FRIENDLY_NAME>(ruleData));
			hashRuleKey.SetDwordValue("HashAlg", hashAlg);
			hashRuleKey.SetBinaryValue("ItemData", get<ITEM_DATA>(ruleData));
			hashRuleKey.SetQwordValue("ItemSize", get<ITEM_SIZE>(ruleData));
			hashRuleKey.SetQwordValue("LastModified", get<LAST_MODIFIED>(ruleData));
			hashRuleKey.SetDwordValue("SaferFlags", 0);	//not used

			hashRuleKey.Close();
			hashRuleKey.Create(
				HKEY_LOCAL_MACHINE,
				policyPath + "\\SHA256",
				KEY_READ | KEY_WRITE);

			hashRuleKey.SetDwordValue("HashAlg", shaHashAlg);
			hashRuleKey.SetBinaryValue("ItemData", get<SHA256_HASH>(ruleData));

			ruleDeleted = true;
		}

		else
		{
			if (get<FRIENDLY_NAME>(ruleData) != hashRuleKey.GetStringValue("FriendlyName"))
			{
				ruleModified = true;
				hashRuleKey.SetStringValue("FriendlyName", get<FRIENDLY_NAME>(ruleData));
			}

			if (hashAlg != hashRuleKey.GetDwordValue("HashAlg"))
			{
				ruleModified = true;
				hashRuleKey.SetDwordValue("HashAlg", hashAlg);
			}

			if (get<ITEM_DATA>(ruleData) != hashRuleKey.GetBinaryValue("ItemData"))
			{
				ruleModified = true;
				hashRuleKey.SetBinaryValue("ItemData", get<ITEM_DATA>(ruleData));
			}

			if (get<ITEM_SIZE>(ruleData) != hashRuleKey.GetQwordValue("ItemSize"))
			{
				ruleModified = true;
				hashRuleKey.SetQwordValue("ItemSize", get<ITEM_SIZE>(ruleData));
			}

			if (get<LAST_MODIFIED>(ruleData) != hashRuleKey.GetQwordValue("LastModified"))
			{
				ruleModified = true;
				hashRuleKey.SetQwordValue("LastModified", get<LAST_MODIFIED>(ruleData));
			}
		}
	
		hashRuleKey.Close();
		
		if (!hashRuleKey.Open(HKEY_LOCAL_MACHINE, policyPath + R"(\SHA256)", KEY_READ | KEY_WRITE))
		{
			hashRuleKey.Create(
				HKEY_LOCAL_MACHINE,
				policyPath + "\\SHA256",
				KEY_READ | KEY_WRITE);

			hashRuleKey.SetQwordValue("ItemSize", get<ITEM_SIZE>(ruleData));
			hashRuleKey.SetQwordValue("LastModified", get<LAST_MODIFIED>(ruleData));

			ruleModified = true;
		}

		else
		{
			if (shaHashAlg != hashRuleKey.GetDwordValue("HashAlg"))
			{
				ruleModified = true;
				hashRuleKey.SetDwordValue("HashAlg", shaHashAlg);
			}

			if (get<SHA256_HASH>(ruleData) != hashRuleKey.GetBinaryValue("ItemData"))
			{
				ruleModified = true;
				hashRuleKey.SetBinaryValue("ItemData", get<SHA256_HASH>(ruleData));
			}
		}

		if (ruleModified)
		{
			SecPolicy::updatedRules++;
			cout << "The rule for " << ruleName << " was modified\n";
		}

		else if (ruleDeleted)
		{
			SecPolicy::createdRules++;
			cout << "\nThe rule for " << ruleName << " was deleted";
		}

		else
			SecPolicy::skippedRules++;
	}
	catch (const RegException &e)
	{
		cerr << '\n' << e.what();
	}
	catch (const exception &e)
	{
		cerr << '\n' << e.what();
	}
}

//gets the version of the file we are creating a rule for
void HashRule::EnumFileVersion(const string_view &fileName)
{
	//Code adapted from crashmstr at
	//https://stackoverflow.com/questions/940707/how-do-i-programmatically-get-the-version-of-a-dll-or-exe-file

	LPCTSTR szVersionFile = fileName.data();
	DWORD verHandle = 0;
	UINT size = 0;
	LPBYTE lpBuffer = nullptr;
	const DWORD  verSize = GetFileVersionInfoSize(szVersionFile, &verHandle);

	if (verSize != NULL)
	{
		auto verData = make_unique<char*>(new char[verSize]);

		if (GetFileVersionInfo(szVersionFile, verHandle, verSize, *verData))
		{
			if (VerQueryValue(*verData, "\\", (VOID FAR* FAR*)&lpBuffer, &size))
			{
				if (size)
				{
					const VS_FIXEDFILEINFO *verInfo = (VS_FIXEDFILEINFO *)lpBuffer;
					if (verInfo->dwSignature == 0xfeef04bd)
					{
						// Doesn't matter if you are on 32 bit or 64 bit,
						// DWORD is always 32 bits, so first two revision numbers
						// come from dwFileVersionMS, last two come from dwFileVersionLS
						fileVersion = " (" +
							to_string((verInfo->dwFileVersionMS >> 16) & 0xffff) + '.' +
							to_string((verInfo->dwFileVersionMS >> 0) & 0xffff) + '.' +
							to_string((verInfo->dwFileVersionLS >> 16) & 0xffff) + '.' +
							to_string((verInfo->dwFileVersionLS >> 0) & 0xffff) + ")";
					}
				}
			}
		}
	}
}

//generates FriendlyName, which is a collection of metadata from the file
void HashRule::EnumFriendlyName(const string_view &fileName)
{
	//Adapted from Henri Hein at
	//http://www.codeguru.com/cpp/w-p/win32/versioning/article.php/c4539/Versioning-in-Windows.htm
	
	LPCTSTR szFile = fileName.data();
	DWORD dwLen, dwUseless;
	LPTSTR lpVI = nullptr;
	WORD* langInfo = nullptr;
	PUINT cbLang = nullptr;
	bool validLang = true;

	dwLen = GetFileVersionInfoSize(szFile, &dwUseless);
	if (dwLen != 0)
	{
		lpVI = static_cast<LPTSTR>(GlobalAlloc(GPTR, dwLen));
		if (lpVI)
		{
			GetFileVersionInfo((LPTSTR)szFile, NULL, dwLen, lpVI);

			validLang = VerQueryValue(lpVI, "\\VarFileInfo\\Translation",
				(LPVOID*)&langInfo, cbLang);
		}
	}
	//if file has no metadata, use alternate method of generating FriendlyName
	if (dwLen == 0 || !validLang)
	{
		//get size on disk
		const auto sizeOnDisk = (4096 * ((itemSize + 4096 - 1) / 4096)) / 1024;
		
		WIN32_FIND_DATA data;
		HANDLE fileHandle = FindFirstFile(fileName.data(), &data);
		FindClose(fileHandle);
		
		//get last write time in the local time zone
		SYSTEMTIME sysTimeUTC, sysTimeLocal;
		FileTimeToSystemTime(&data.ftLastWriteTime, &sysTimeUTC);
		SystemTimeToTzSpecificLocalTime(nullptr, &sysTimeUTC, &sysTimeLocal);
		string timeStamp = to_string(sysTimeLocal.wMonth) + "/"
			+ to_string(sysTimeLocal.wDay) + "/" + to_string(sysTimeLocal.wYear)
			+ " " + to_string(sysTimeLocal.wHour) + ":"
			+ to_string(sysTimeLocal.wMinute) + ":" + to_string(sysTimeLocal.wSecond);

		friendlyName = fileName.substr(fileName.rfind('\\') + 1, fileName.length()).data() + 
			to_string(sizeOnDisk) + "  KB" + timeStamp;
	}
	else
	{
		EnumFileVersion(fileName);
			
		TCHAR tszVerStrName[128];
		LPVOID lpt;
		PUINT cbBufSize = nullptr;
		string temp[6];

		for (int i = 0; i < 5; i++)
		{
			//Prepare the label to get the metadata types in fileProps
			temp[i] = "\\StringFileInfo\\%04x%04x\\" + fileProps[i];
			StringCchPrintf(tszVerStrName, STRSAFE_MAX_CCH,
				temp[i].c_str(),
				langInfo[0], langInfo[1]);
			//Get the string from the resource data
			if (VerQueryValue(lpVI, tszVerStrName, &lpt, cbBufSize))
				temp[i] = (LPTSTR)lpt;
			//if the file is missing certain metadata, skip it
			else
				temp[i].clear();
		}

		//format FriendlyName
		friendlyName = temp[0] + fileVersion;
		for (int i = 1; i < 5; i++)
			friendlyName += temp[i];

		//Cleanup
		GlobalFree((HGLOBAL)lpVI);
	}
}

//gets current time 
inline void HashRule::EnumCreationTime() noexcept
{
	FILETIME currTime;
	GetSystemTimeAsFileTime(&currTime);

	lastModified = currTime.dwLowDateTime |
		currTime.dwHighDateTime << 32;
}

void HashRule::HashDigests(const string_view &fileName)
{
	using namespace CryptoPP;

	Weak::MD5 md5Hash;
	SHA256 shaHash;
	string md5Digest;
	string shaDigest;
	
	FileSource(
		fileName.data(), true, new HashFilter(
			md5Hash, new HexEncoder(new StringSink(md5Digest))));

	FileSource(
		fileName.data(), true, new HashFilter(
			shaHash, new HexEncoder(new StringSink(shaDigest))));

	//convert string to format that can be loaded into registry
	itemData = convertStrToByte(md5Digest);
	sha256Hash = convertStrToByte(shaDigest);
}

//converts string of hex into bytes
inline vector<BYTE> HashRule::convertStrToByte(string &str) noexcept
{
	vector<BYTE> vec;
	for (unsigned i = 0; i < str.length(); i += 2)
	{
		// Convert hex char to byte
		if (str[i] >= '0' && str[i] <= '9') str[i] -= '0';
		else str[i] -= 55;
		if (str[i + 1] >= '0' && str[i + 1] <= '9') str[i + 1] -= '0';
		else str[i + 1] -= 55;

		vec.emplace_back((str[i] << 4) | str[i + 1]);
	}
	return vec;
}

//generates random GUID
inline void HashRule::CreateGUID()
{
	//make new GUID in the small chance that CoCreateGuid fails
	bool goodGUID;
	do {
		goodGUID = MakeGUID();
	} while (!goodGUID);
}

inline bool HashRule::MakeGUID()
{
	bool result;
	GUID rGUID;
	const HRESULT hr = CoCreateGuid(&rGUID);

	if (hr == S_OK)
	{
		wchar_t szGuidW[40] = { 0 };
		char szGuidA[40] = { 0 };

		StringFromGUID2(rGUID, szGuidW, 40);
		WideCharToMultiByte(CP_ACP, 0, szGuidW, -1, szGuidA, 40, nullptr, nullptr);
		
		guid = szGuidA;
		for (auto &GUIDchar : guid)
		{
			if (isalpha(GUIDchar))
				GUIDchar = tolower(GUIDchar);
		}

		result = true;
	}
		
	else
		result = false;

	return result;
}

//write the hash rule to the registry
void HashRule::WriteToRegistry(const string_view &fileName, SecOption policy)
{
	using namespace winreg;

	try
	{
		string policyPath = [&]()
		{
			if (policy == SecOption::BLACKLIST)
				return R"(SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Hashes\)" + guid;
			else
				return R"(SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\262144\Hashes\)" + guid;
		} ();

		RegKey hashRuleKey(
			HKEY_LOCAL_MACHINE,
			policyPath,
			KEY_WRITE);

		hashRuleKey.SetStringValue("Description", fileName);
		hashRuleKey.SetStringValue("FriendlyName", friendlyName);
		hashRuleKey.SetDwordValue("HashAlg", hashAlg);
		hashRuleKey.SetBinaryValue("ItemData", itemData);
		hashRuleKey.SetQwordValue("ItemSize", itemSize);
		hashRuleKey.SetQwordValue("LastModified", lastModified);
		hashRuleKey.SetDwordValue("SaferFlags", 0);	//not used

		hashRuleKey.Close();
		hashRuleKey.Create(
			HKEY_LOCAL_MACHINE,
			policyPath + "\\SHA256",
			KEY_WRITE);

		hashRuleKey.SetDwordValue("HashAlg", shaHashAlg);
		hashRuleKey.SetBinaryValue("ItemData", sha256Hash);
	}
	catch (const RegException &e)
	{
		cout << e.what() << endl;
	}
	catch (const exception &e)
	{
		cout << e.what() << endl;
	}
}