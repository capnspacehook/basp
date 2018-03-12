#include "AppSecPolicy.hpp"
#include "CliParser.hpp"
#include "SecPolicy.hpp"
#include "HashRule.hpp"

#include "include\clara.hpp"

using namespace std;
using namespace AppSecPolicy;

void CheckElevated();
bool RemovePrivilege(const char*);

int main(int argc, char *argv[])
{
	//CheckElevated();
	RemovePrivilege("SeAssignPrimaryTokenPrivilege");
	RemovePrivilege("SeCreateTokenPrivilege");
	RemovePrivilege("SeDebugPrivilege");
	RemovePrivilege("SeIncreaseQuotaPrivilege");
	RemovePrivilege("SeLoadDriverPrivilege");
	RemovePrivilege("SeRestorePrivilege");
	RemovePrivilege("SeShutdownPrivilege");
	RemovePrivilege("SeSystemEnvironmentPrivilege");
	RemovePrivilege("SeSystemtimePrivilege");
	RemovePrivilege("SeTcbPrivilege");

	CliParser parser(argc, argv);

	SecPolicy secPolicy(move(parser.programName), move(parser.password), parser.updatingRules, 
		parser.listRules, parser.listAllRules);

	if (parser.changePassword)
		secPolicy.ChangePassword();

	if (parser.checkRules)
		secPolicy.CheckRules();

	/*if (parser.defaultPolicy)
		secPolicy.DefaultPolicy();*/

	if (parser.blacklisting)
		secPolicy.CreatePolicy(parser.fileArgs, SecOption::BLACKLIST);

	else if (parser.whitelisting)
		secPolicy.CreatePolicy(parser.fileArgs, SecOption::WHITELIST);

	else if (parser.updatingRules)
		secPolicy.UpdateRules(parser.fileArgs);

	else if (parser.removingRules)
		secPolicy.RemoveRules(parser.fileArgs);

	else if (!parser.tempAllowFile.empty())
	{
		if (parser.tempAllowParentDir)
			secPolicy.TempRun(parser.parentDir, parser.tempAllowFile);

		else
			secPolicy.TempRun(parser.tempAllowFile);
	}

	else if (!parser.tempAllowDir.empty())
		secPolicy.TempRun(parser.tempAllowDir, parser.tempAllowExe);
}

void CheckElevated()
{
	bool fRet = false;
	HANDLE hToken = nullptr;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
	{
		TOKEN_ELEVATION Elevation;
		DWORD cbSize = sizeof(TOKEN_ELEVATION);
		if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize))
			fRet = Elevation.TokenIsElevated;
	}
	if (hToken)
		CloseHandle(hToken);

	if (!fRet)
	{
		cout << "This program requires administrator access to function correctly.\n"
			<< "Please rerun this program again as an Administrator.\n";
		exit(-1);
	}
}

bool RemovePrivilege(const char* privName)
{
	HANDLE tokenH;
	HANDLE localProc = GetCurrentProcess();
	if (!OpenProcessToken(localProc, TOKEN_ADJUST_PRIVILEGES, &tokenH))
	{
		cerr << "OpenProcessToken error: " << GetLastError();
		return false;
	}

	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!LookupPrivilegeValue(
		nullptr,            // lookup privilege on local system
		privName,   // privilege to lookup 
		&luid))        // receives LUID of privilege
	{
		cerr << "LookupPrivilegeValue error: " << GetLastError() << '\n';
		return false;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	//tp.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED;

	// Enable the privilege or disable all privileges.

	if (!AdjustTokenPrivileges(
		tokenH,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)nullptr,
		(PDWORD)nullptr))
	{
		cerr << "AdjustTokenPrivileges error: " << GetLastError() << '\n';
		return false;
	}

	return true;
}