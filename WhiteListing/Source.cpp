#include "AppSecPolicy.hpp"
#include "SecPolicy.hpp"
#include "HashRule.hpp"
#include "WinReg.hpp"
#include "Windows.h"

#include <iostream>	
#include <string>

using namespace std;
using namespace AppSecPolicy;

bool IsElevated();
void GPForceUpdate();

int main(int argc, char *argv[])
{
	if (!IsElevated())
	{
		cout << "This program requires administrator access to function correctly."
			<< "Please run this program again as an Administrator." << endl;
		return -1;
	}

	if (argc < 2)
	{
		cout << "Usage: " << argv[0] << " [file path]" << endl;
		return -1;
	}

	SecPolicy(argv[1], SecOptions::BLACKLIST);

	GPForceUpdate();
}

bool IsElevated()
{
	bool fRet = false;
	HANDLE hToken = NULL;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
	{
		TOKEN_ELEVATION Elevation;
		DWORD cbSize = sizeof(TOKEN_ELEVATION);
		if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize))
			fRet = Elevation.TokenIsElevated;
	}
	if (hToken)
		CloseHandle(hToken);

	return fRet;
}

//force a Group Policy Update after we're done
void GPForceUpdate() {
	// additional information
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	SecureZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	SecureZeroMemory(&pi, sizeof(pi));

	cout << endl;

	// start the program up
	CreateProcess("C:\\Windows\\System32\\gpupdate.exe",   // the path
		" /target:computer /force",        // Command line
		NULL,           // Process handle not inheritable
		NULL,           // Thread handle not inheritable
		FALSE,          // Set handle inheritance to FALSE
		0,              // No creation flags
		NULL,           // Use parent's environment block
		NULL,           // Use parent's starting directory 
		&si,            // Pointer to STARTUPINFO structure
		&pi             // Pointer to PROCESS_INFORMATION structure (removed extra parentheses)
	);

	//send process to sleep so more code doesnt run
	Sleep(7500);
	// Close process and thread handles. 
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
}