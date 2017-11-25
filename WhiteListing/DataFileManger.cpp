#include "AppSecPolicy.hpp"
#include "DataFileManger.hpp"
#include "WinReg.hpp"
#include "Windows.h"

#include "Crypto++\pwdbased.h"
#include "Crypto++\filters.h"
#include "Crypto++\osrng.h"
#include "Crypto++\files.h"
#include "Crypto++\hex.h"
#include "Crypto++\sha.h"
#include "Crypto++\aes.h"
#include "Crypto++\gcm.h"

#include <filesystem>
#include <exception>
#include <iostream>
#include <fstream>
#include <vector>
#include <thread>
#include <string>

using namespace std;
using namespace CryptoPP;
namespace fs = std::experimental::filesystem;

bool DataFileManager::FindDataFile()
{
	fs::path currDir = fs::current_path();

	for (const auto &currFile : fs::directory_iterator(currDir))
	{

	}
	return false;
}

void DataFileManager::OpenPolicyFile()
{
	GCM<AES>::Decryption decryptor;
	decryptor.SetKeyWithIV(kdfHash.data(), KEY_SIZE, kdfHash.data() + KEY_SIZE, KEY_SIZE);

	AuthenticatedDecryptionFilter adf(decryptor, new StringSink(*policyData),
		AuthenticatedDecryptionFilter::DEFAULT_FLAGS, TAG_SIZE);
	FileSource(policyFileName.c_str(), true, new Redirector(adf));

	if (adf.GetLastResult() != true)
		cerr << "File modified!" << endl;

	policyData.ProtectMemory(true);
}

void DataFileManager::ClosePolicyFile()
{
	GCM<AES>::Encryption encryptor;
	encryptor.SetKeyWithIV(kdfHash.data(), KEY_SIZE, kdfHash.data() + KEY_SIZE, KEY_SIZE);

	StringSource(*policyData, true, new AuthenticatedEncryptionFilter(
		encryptor, new FileSink(policyFileName.c_str()), false, TAG_SIZE));

	policyData->clear();
	policyData.ProtectMemory(true);
}

void DataFileManager::SetNewPassword()
{
	string newPass1, newPass2;
	bool passesMismatch = true;

	do 
	{
		cout << "Enter your new password:\n";
		GetPassword(newPass1);

		cout << "Enter it again:\n";
		GetPassword(newPass2);

		if (newPass1 != newPass2)
			cout << "Passwords do not match. Please enter again.\n";
		else
			passesMismatch = false;
	} while (passesMismatch);
	SecureWipeArray(&newPass1, newPass1.size());

	AutoSeededRandomPool rng;
	rng.GenerateBlock(kdfSalt, KEY_SIZE);

	PKCS5_PBKDF2_HMAC<SHA256> kdf;
	kdf.DeriveKey(
		kdfHash.data(),
		kdfHash.size(),
		0,
		(byte*)newPass2.data(),
		newPass2.size(),
		kdfSalt.data(),
		kdfSalt.size(),
		iterations);

	SecureWipeArray(&newPass2, newPass2.size());
	ClosePolicyFile();
}

void DataFileManager::CheckPassword()
{
	string password; 
	cout << "Enter the password:\n";
	GetPassword(password);

	PKCS5_PBKDF2_HMAC<SHA256> kdf;
	kdf.DeriveKey(
		kdfHash.data(),
		kdfHash.size(),
		0,
		(byte*)password.data(),
		password.size(),
		kdfSalt.data(),
		kdfSalt.size(),
		iterations);
	
	SecureWipeArray(password.data(), password.size());
	OpenPolicyFile();
}

//securely get password from user
void DataFileManager::GetPassword(string &password)
{
	//set console to not show typed password
	HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
	DWORD mode = 0;
	GetConsoleMode(hStdin, &mode);
	SetConsoleMode(hStdin, mode & (~ENABLE_ECHO_INPUT));
	
	getline(cin, password);

	//reset console to normal
	SetConsoleMode(hStdin, mode);
}