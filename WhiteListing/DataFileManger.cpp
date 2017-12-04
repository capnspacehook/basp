#include "AppSecPolicy.hpp"
#include "DataFileManger.hpp"
#include "ProtectedPtr.hpp"
#include "Windows.h"

#include "Crypto++\pwdbased.h"
#include "Crypto++\filters.h"
#include "Crypto++\osrng.h"
#include "Crypto++\files.h"
#include "Crypto++\sha.h"
#include "Crypto++\aes.h"
#include "Crypto++\gcm.h"

#include <exception>
#include <iostream>
#include <fstream>
#include <thread>
#include <string>

using namespace std;
using namespace CryptoPP;
using namespace AppSecPolicy;
using namespace Protected_Ptr;

bool DataFileManager::OpenPolicyFile(bool writeChanges)
{
	string temp;
	bool goodOpen = true;

	GCM<AES>::Decryption decryptor;
	decryptor.SetKeyWithIV(kdfHash->data(), KEY_SIZE, kdfHash->data() + KEY_SIZE, KEY_SIZE);
	kdfHash.ProtectMemory(true);

	AuthenticatedDecryptionFilter adf(decryptor, new StringSink(temp),
		AuthenticatedDecryptionFilter::MAC_AT_END, TAG_SIZE);
	FileSource encPolicyFile(policyFileName.c_str(), false);
	//skip part containing the salt
	encPolicyFile.Pump(KEY_SIZE);
	encPolicyFile.Attach(new Redirector(adf));
	encPolicyFile.PumpAll();

	if (temp.substr(0, policyFileHeader.size()) != policyFileHeader)
		goodOpen = false;

	else
		if (adf.GetLastResult() != true)
		{
			goodOpen = false;
			cerr << "File modified!" << endl;
		}


	if (goodOpen && writeChanges)
	{
		*policyData = temp;
		policyData.ProtectMemory(true);
	}

	SecureZeroMemory(&temp, sizeof(temp));

	return goodOpen;
}

void DataFileManager::ClosePolicyFile()
{
	GCM<AES>::Encryption encryptor;
	encryptor.SetKeyWithIV(kdfHash->data(), KEY_SIZE, kdfHash->data() + KEY_SIZE, KEY_SIZE);
	kdfHash.ProtectMemory(true);

	//place salt unencrypted in beginning of file
	FileSink file(policyFileName.c_str());
	ArraySource as(*kdfSalt, kdfSalt->size(), true,
		new Redirector(file));
	kdfSalt.ProtectMemory(true);

	//prepend header and dummy data that will be skipped
	policyData->insert(0, policyFileHeader);
	policyData->insert(0, KEY_SIZE, 'A');

	StringSource updatedData(*policyData, false);
	//skip part containing the salt
	updatedData.Pump(KEY_SIZE);
	updatedData.Attach(new AuthenticatedEncryptionFilter(
		encryptor, new Redirector(file), false, TAG_SIZE));
	updatedData.PumpAll();

	policyData.ProtectMemory(true);
}

void DataFileManager::WriteToFile(const RuleData& rulesInfo)
{
	int option;
	int type;
	string location;
	string* guid;

	for (const auto& rule : rulesInfo)
	{
		option = static_cast<int>(get<SEC_OPTION>(rule));
		type = static_cast<int>(get<RULE_TYPE>(rule));
		location = get<FILE_LOCATION>(rule);
		guid = get<RULE_GUID>(rule);

		*policyData += to_string(option) + " " + to_string(type)
			+ " " + location + " " + *guid + "\n";
	}

	policyData.ProtectMemory(true);
}

void DataFileManager::WriteChanges()
{
	OpenPolicyFile(false);
	ClosePolicyFile();
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

	cout << "Computing new password hash...";
	SecureZeroMemory(&newPass1, sizeof(newPass1));

	AutoSeededRandomPool prng;
	prng.GenerateBlock(*kdfSalt, KEY_SIZE);

	PKCS5_PBKDF2_HMAC<SHA256> kdf;
	kdf.DeriveKey(
		kdfHash->data(),
		kdfHash->size(),
		0,
		(byte*)newPass2.data(),
		newPass2.size(),
		kdfSalt->data(),
		kdfSalt->size(),
		iterations);

	SecureZeroMemory(&newPass2, sizeof(newPass2));
	
	kdfHash.ProtectMemory(true);
	kdfSalt.ProtectMemory(true);

	cout << "done" << endl;

	ClosePolicyFile();
}

void DataFileManager::CheckPassword()
{
	string salt, password;
	bool validPwd;
	
	//get salt from beginning of file
	FileSource encPolicyFile(policyFileName.c_str(), false);
	encPolicyFile.Attach(new ArraySink(*kdfSalt, kdfSalt->size()));
	encPolicyFile.Pump(KEY_SIZE);
	
	do
	{
		cout << "Enter the password:\n";
		GetPassword(password);
		cout << "Verifying password...";

		PKCS5_PBKDF2_HMAC<SHA256> kdf;
		kdf.DeriveKey(
			kdfHash->data(),
			kdfHash->size(),
			0,
			(byte*)password.data(),
			password.size(),
			kdfSalt->data(),
			kdfSalt->size(),
			iterations);

		kdfHash.ProtectMemory(true);
		kdfSalt.ProtectMemory(true);

		validPwd = OpenPolicyFile(true);

		if (validPwd)
			cout << "done\n";
		else
			cout << "\nInvalid password entered\n";

	} while (!validPwd);

	SecureZeroMemory(&password, sizeof(password));
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