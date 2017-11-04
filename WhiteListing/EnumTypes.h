#include "windows.h"
#include "strsafe.h"
#pragma once

HANDLE g_hFile;

BOOL EnumTypesFunc(
	HMODULE hModule,
	LPTSTR lpType,
	LONG lParam);

BOOL EnumNamesFunc(
	HMODULE hModule,
	LPCTSTR lpType,
	LPTSTR lpName,
	LONG lParam);

BOOL EnumLangsFunc(
	HMODULE hModule,
	LPCTSTR lpType,
	LPCTSTR lpName,
	WORD wLang,
	LONG lParam);

//    FUNCTION: EnumTypesFunc(HANDLE, LPSTR, LONG)
//
//    PURPOSE:  Resource type callback
BOOL EnumTypesFunc(
	HMODULE hModule,  // module handle
	LPTSTR lpType,    // address of resource type
	LONG lParam)      // extra parameter, could be
					  // used for error checking
{
	TCHAR szBuffer[80];  // print buffer for info file
	DWORD cbWritten;     // number of bytes written to resource info file
	size_t cbString;
	HRESULT hResult;

	// Write the resource type to a resource information file.
	// The type may be a string or an unsigned decimal
	// integer, so test before printing.
	if (!IS_INTRESOURCE(lpType))
	{
		hResult = StringCchPrintf(szBuffer, sizeof(szBuffer) / sizeof(TCHAR), TEXT("Type: %s\r\n"), lpType);
		if (FAILED(hResult))
		{
			// Add code to fail as securely as possible.
			return FALSE;
		}
	}
	else
	{
		hResult = StringCchPrintf(szBuffer, sizeof(szBuffer) / sizeof(TCHAR), TEXT("Type: %u\r\n"), (USHORT)lpType);
		if (FAILED(hResult))
		{
			// Add code to fail as securely as possible.
			return FALSE;
		}
	}

	hResult = StringCchLength(szBuffer, sizeof(szBuffer) / sizeof(TCHAR), &cbString);
	if (FAILED(hResult))
	{
		// Add code to fail as securely as possible.
		return FALSE;
	}

	WriteFile(g_hFile, szBuffer, (DWORD)cbString, &cbWritten, NULL);
	// Find the names of all resources of type lpType.
	EnumResourceNames(hModule,
		lpType,
		(ENUMRESNAMEPROC)EnumNamesFunc,
		0);

	return TRUE;
}

//    FUNCTION: EnumNamesFunc(HANDLE, LPSTR, LPSTR, LONG)
//
//    PURPOSE:  Resource name callback
BOOL EnumNamesFunc(
	HMODULE hModule,  // module handle
	LPCTSTR lpType,   // address of resource type
	LPTSTR lpName,    // address of resource name
	LONG lParam)      // extra parameter, could be
					  // used for error checking
{
	TCHAR szBuffer[80];  // print buffer for info file
	DWORD cbWritten;     // number of bytes written to resource info file
	size_t cbString;
	HRESULT hResult;

	// Write the resource name to a resource information file.
	// The name may be a string or an unsigned decimal
	// integer, so test before printing.
	if (!IS_INTRESOURCE(lpName))
	{
		hResult = StringCchPrintf(szBuffer, sizeof(szBuffer) / sizeof(TCHAR), TEXT("\tName: %s\r\n"), lpName);
		if (FAILED(hResult))
		{
			// Add code to fail as securely as possible.
			return FALSE;
		}
	}
	else
	{
		hResult = StringCchPrintf(szBuffer, sizeof(szBuffer) / sizeof(TCHAR), TEXT("\tName: %u\r\n"), (USHORT)lpName);
		if (FAILED(hResult))
		{
			// Add code to fail as securely as possible.
			return FALSE;
		}
	}

	hResult = StringCchLength(szBuffer, sizeof(szBuffer) / sizeof(TCHAR), &cbString);
	if (FAILED(hResult))
	{
		// Add code to fail as securely as possible.
		return FALSE;
	}

	WriteFile(g_hFile, szBuffer, (DWORD)cbString, &cbWritten, NULL);
	// Find the languages of all resources of type
	// lpType and name lpName.
	EnumResourceLanguages(hModule,
		lpType,
		lpName,
		(ENUMRESLANGPROC)EnumLangsFunc,
		0);

	return TRUE;
}

//    FUNCTION: EnumLangsFunc(HANDLE, LPSTR, LPSTR, WORD, LONG)
//
//    PURPOSE:  Resource language callback
BOOL EnumLangsFunc(
	HMODULE hModule, // module handle
	LPCTSTR lpType,  // address of resource type
	LPCTSTR lpName,  // address of resource name
	WORD wLang,      // resource language
	LONG lParam)     // extra parameter, could be
					 // used for error checking
{
	HRSRC hResInfo;
	TCHAR szBuffer[80];  // print buffer for info file
	DWORD cbWritten;     // number of bytes written to resource info file
	size_t cbString;
	HRESULT hResult;

	hResInfo = FindResourceEx(hModule, lpType, lpName, wLang);
	// Write the resource language to the resource information file.
	hResult = StringCchPrintf(szBuffer, sizeof(szBuffer) / sizeof(TCHAR), TEXT("\t\tLanguage: %u\r\n"), (USHORT)wLang);
	if (FAILED(hResult))
	{
		// Add code to fail as securely as possible.
		return FALSE;
	}

	hResult = StringCchLength(szBuffer, sizeof(szBuffer) / sizeof(TCHAR), &cbString);
	if (FAILED(hResult))
	{
		// Add code to fail as securely as possible.
		return FALSE;
	}

	WriteFile(g_hFile, szBuffer, (DWORD)cbString, &cbWritten, NULL);
	// Write the resource handle and size to buffer.
	hResult = StringCchPrintf(szBuffer,
		sizeof(szBuffer) / sizeof(TCHAR),
		TEXT("\t\thResInfo == %lx,  Size == %lu\r\n\r\n"),
		hResInfo,
		SizeofResource(hModule, hResInfo));
	if (FAILED(hResult))
	{
		// Add code to fail as securely as possible.
		return FALSE;
	}

	hResult = StringCchLength(szBuffer, sizeof(szBuffer) / sizeof(TCHAR), &cbString);
	if (FAILED(hResult))
	{
		// Add code to fail as securely as possible.
		return FALSE;
	}

	WriteFile(g_hFile, szBuffer, (DWORD)cbString, &cbWritten, NULL);
	return TRUE;
}
