#include "AppSecPolicy.hpp"
#include "HashRule.hpp"
#include "WinReg.hpp"

#include "Windows.h"
#include "Strsafe.h"
#include "Rpc.h"

//nessesary for md5 to function 
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include "Crypto++\hex.h"
#include "Crypto++\files.h"
#include "Crypto++\filters.h"
#include "Crypto++\md5.h"
#include "Crypto++\sha.h"

#include <exception>
#include <string>
#include <vector>

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

//sets the 'subKey' parameter to the rule's guid
void HashRule::CreateNewHashRule(const string &fileName,
	const SecOption &secOption, const uintmax_t &fileSize, std::shared_ptr<std::string> subKey)
{
	itemSize = fileSize;
	EnumFriendlyName(fileName);
	EnumCreationTime();
	HashDigests(fileName);
	CreateGUID();
	WriteToRegistry(fileName, secOption);
	*subKey = guid;
}

void HashRule::EnumFileVersion(const string &fileName)
{
	//Code adapted from crashmstr at
	//https://stackoverflow.com/questions/940707/how-do-i-programmatically-get-the-version-of-a-dll-or-exe-file

	LPCTSTR szVersionFile = fileName.c_str();
	DWORD  verHandle = 0;
	UINT   size = 0;
	LPBYTE lpBuffer = NULL;
	DWORD  verSize = GetFileVersionInfoSize(szVersionFile, &verHandle);

	if (verSize != NULL)
	{
		LPSTR verData = new char[verSize];

		if (GetFileVersionInfo(szVersionFile, verHandle, verSize, verData))
		{
			if (VerQueryValue(verData, TEXT("\\"), (VOID FAR* FAR*)&lpBuffer, &size))
			{
				if (size)
				{
					VS_FIXEDFILEINFO *verInfo = (VS_FIXEDFILEINFO *)lpBuffer;
					if (verInfo->dwSignature == 0xfeef04bd)
					{
						char s[50];
						// Doesn't matter if you are on 32 bit or 64 bit,
						// DWORD is always 32 bits, so first two revision numbers
						// come from dwFileVersionMS, last two come from dwFileVersionLS
						snprintf(s, 50, "%d.%d.%d.%d",
							(verInfo->dwFileVersionMS >> 16) & 0xffff,
							(verInfo->dwFileVersionMS >> 0) & 0xffff,
							(verInfo->dwFileVersionLS >> 16) & 0xffff,
							(verInfo->dwFileVersionLS >> 0) & 0xffff
						);

						fileVersion = s;
						fileVersion = " (" + fileVersion + ")";
					}
				}
			}
		}
		delete[] verData;
	}

}

//Generates FriendlyName, which is a collection of metadata from the file
void HashRule::EnumFriendlyName(const string &fileName)
{
	//Adapted from Henri Hein at
	//http://www.codeguru.com/cpp/w-p/win32/versioning/article.php/c4539/Versioning-in-Windows.htm
	
	LPCTSTR szFile = fileName.c_str();
	DWORD dwLen, dwUseless;
	LPTSTR lpVI = NULL;
	WORD* langInfo = NULL;
	PUINT cbLang = 0;
	bool validLang = true;

	dwLen = GetFileVersionInfoSize(szFile, &dwUseless);
	if (dwLen != 0)
	{
		lpVI = (LPTSTR)GlobalAlloc(GPTR, dwLen);
		if (lpVI)
		{
			GetFileVersionInfo((LPTSTR)szFile, NULL, dwLen, lpVI);

			validLang = VerQueryValue(lpVI, TEXT("\\VarFileInfo\\Translation"),
				(LPVOID*)&langInfo, cbLang);
		}
	}
	//if file has no metadata, use alternate method of generating FriendlyName
	if (dwLen == 0 || !validLang)
	{
		//get size on disk
		string originalName = fileName.substr(
			fileName.rfind("\\") + 1,
			fileName.length());
		int sizeOnDisk = (4096 * ((itemSize + 4096 - 1) / 4096)) / 1024;
		
		WIN32_FIND_DATA data;
		HANDLE h = FindFirstFile(fileName.c_str(), &data);
		
		//get last write time in the local time zone
		SYSTEMTIME sysTimeUTC, sysTimeLocal;
		FileTimeToSystemTime(&data.ftLastWriteTime, &sysTimeUTC);
		SystemTimeToTzSpecificLocalTime(NULL, &sysTimeUTC, &sysTimeLocal);
		string lastModified = to_string(sysTimeLocal.wMonth) + "/"
			+ to_string(sysTimeLocal.wDay) + "/" + to_string(sysTimeLocal.wYear)
			+ " " + to_string(sysTimeLocal.wHour) + ":"
			+ to_string(sysTimeLocal.wMinute) + ":" + to_string(sysTimeLocal.wSecond);

		friendlyName = originalName + to_string(sizeOnDisk) + "  KB" + lastModified;
	}
	else
	{
		EnumFileVersion(fileName);
			
		TCHAR tszVerStrName[128];
		LPVOID lpt;
		PUINT cbBufSize = 0;
		string temp[6];

		for (int i = 0; i < 5; i++)
		{
			//Prepare the label to get the metadata types in fileProps
			temp[i] = "\\StringFileInfo\\%04x%04x\\" + fileProps[i];
			StringCchPrintf(tszVerStrName, STRSAFE_MAX_CCH,
				TEXT(temp[i].c_str()),
				langInfo[0], langInfo[1]);
			//Get the string from the resource data
			if (VerQueryValue(lpVI, tszVerStrName, &lpt, cbBufSize))
				temp[i] = (LPTSTR)lpt;
			//if the file is missing certain metadata, skip it
			else
				temp[i] = "";
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
inline void HashRule::EnumCreationTime()
{
	FILETIME currTime;
	GetSystemTimeAsFileTime(&currTime);

	lastModified = currTime.dwLowDateTime |
		(long long)currTime.dwHighDateTime << 32;
}

void HashRule::HashDigests(const string &fileName)
{
	using namespace CryptoPP;

	Weak::MD5 md5Hash;
	SHA256 shaHash;
	string md5Digest;
	string shaDigest;
	
	FileSource(
		fileName.c_str(), true, new HashFilter(
			md5Hash, new HexEncoder(new StringSink(md5Digest))));

	FileSource(
		fileName.c_str(), true, new HashFilter(
			shaHash, new HexEncoder(new StringSink(shaDigest))));

	//convert string to format that can be loaded into registry
	itemData = move(convertStrToByte(md5Digest));
	sha256Hash = move(convertStrToByte(shaDigest));
}

//converts string of hex into bytes
inline vector<BYTE> HashRule::convertStrToByte(string &str) noexcept
{
	vector<BYTE> vec;
	for (int i = 0; i < str.length(); i += 2)
	{
		// Convert hex char to byte
		if (str[i] >= '0' && str[i] <= '9') str[i] -= '0';
		else str[i] -= 55;  // 55 = 'str[i]' - 10
		if (str[i + 1] >= '0' && str[i + 1] <= '9') str[i + 1] -= '0';
		else str[i + 1] -= 55;

		vec.push_back((str[i] << 4) | str[i + 1]);
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
	HRESULT hr = CoCreateGuid(&rGUID);

	if (hr == S_OK)
	{
		wchar_t szGuidW[40] = { 0 };
		char szGuidA[40] = { 0 };

		StringFromGUID2(rGUID, szGuidW, 40);
		WideCharToMultiByte(CP_ACP, 0, szGuidW, -1, szGuidA, 40, NULL, NULL);
		
		guid = szGuidA;
		for (int i = 0; i < guid.length(); i++)
		{
			if (isalpha(guid[i]))
				guid[i] = tolower(guid[i]);
		}

		result = true;
	}
		
	else
		result = false;

	return result;
}

//write the hash rule to the registry
void HashRule::WriteToRegistry(const string &fileName,
	const SecOption &policy)
{
	using namespace winreg;

	try
	{
		string ruleType;
		string policyPath =
			"SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers";

		if (policy == SecOption::BLACKLIST)
			ruleType = "\\0\\Hashes\\";
		else
			ruleType = "\\262144\\Hashes\\";

		policyPath += ruleType + guid;

		RegKey hashRuleKey(
			HKEY_LOCAL_MACHINE,
			policyPath,
			KEY_WRITE
		);

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

void HashRule::SwitchRule(const std::string &ruleGuid, SecOption option)
{
	using namespace winreg;
	
	try
	{ 
		string fileName;
		string ruleType;
		string rulePath;
		string policyPath =
			"SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers";

		guid = ruleGuid;

		if (option == SecOption::WHITELIST)
			ruleType = "\\0\\Hashes\\";
		else
			ruleType = "\\262144\\Hashes\\";

		policyPath += ruleType;
		rulePath += policyPath + guid;

		//get values of already created rule
		RegKey hashRuleKey(
			HKEY_LOCAL_MACHINE,
			rulePath,
			KEY_READ
		);

		fileName = hashRuleKey.GetStringValue("Description");
		friendlyName = hashRuleKey.GetStringValue("FriendlyName");
		itemData = hashRuleKey.GetBinaryValue("ItemData");
		itemSize = hashRuleKey.GetQwordValue("ItemSize");
		EnumCreationTime();

		hashRuleKey.Close();
		hashRuleKey.Open(
			HKEY_LOCAL_MACHINE,
			rulePath + "\\SHA256",
			KEY_READ);

		sha256Hash = hashRuleKey.GetBinaryValue("ItemData");

		WriteToRegistry(fileName, option);

		//flip option and delete old rule
		option = static_cast<SecOption>(!static_cast<bool>(option));
		RemoveRule(guid, option);
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

void HashRule::RemoveRule(const string &guid, const SecOption &policy)
{
	using namespace winreg;

	try
	{
		string ruleType;
		string policyPath =
			"SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers";

		if (policy == SecOption::BLACKLIST)
			ruleType = "\\0\\Hashes\\";
		else
			ruleType = "\\262144\\Hashes\\";

		policyPath += ruleType;

		RegKey tempKey(
			HKEY_LOCAL_MACHINE,
			policyPath,
			DELETE
			);

		tempKey.DeleteKey(guid + "\\SHA256", KEY_WOW64_32KEY);
		tempKey.DeleteKey(guid, KEY_WOW64_32KEY);
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