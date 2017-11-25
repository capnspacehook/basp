#include "Windows.h"
#include "Wincrypt.h"
#include <memory>

#pragma comment(lib, "crypt32.lib")
#pragma once

template <class T>
class Protected
{
public:
	explicit Protected() : protectedData(nullptr) {};
	explicit Protected(T *obj, bool encrypt = true)
	{ 
		assign(obj);
		if (encrypt)
			ProtectMemory(protectedData, true); 
	}
	explicit Protected(const Protected& rhs) : protectedData(nullptr)
	{
		if(rhs)
			protectedData = rhs.protectedData;

		isEncrypted = rhs.isEncrypted;
	}
	explicit Protected(Protected&& rhs) : protectedData(nullptr) noexcept
	{
		rhs.swap(*this);
	}
	~Protected() 
	{ 
		ProtectMemory(false); 
		SecureWipeData();
	}

	bool IsProtected() const { return isEncrypted };
	void ProtectMemory(bool encrypt)
	{
		size_t mod;
		size_t dataBlockSize;
		size_t dataSize = sizeof(*protectedData);

		if (mod = dataSize % CRYPTPROTECTMEMORY_BLOCK_SIZE)
			dataBlockSize = dataSize + (CRYPTPROTECTMEMORY_BLOCK_SIZE - mod);
		else
			dataBlockSize = dataSize;
		if (encrypt && !isEncrypted)
		{
			isEncrypted = true;
			if (!CryptProtectMemory(getRawPtr(), dataBlockSize,
				CRYPTPROTECTMEMORY_SAME_PROCESS))
			{
				cerr << "CryptProtectMemory failed: " << GetLastError() << endl;
			}
		}
		else if (!encrypt && isEncrypted)
		{
			isEncrypted = false;
			if (!CryptUnprotectMemory(getRawPtr(), dataBlockSize,
				CRYPTPROTECTMEMORY_SAME_PROCESS))
			{
				cerr << "CryptProtectMemory failed: " << GetLastError() << endl;
			}
		}

		SecureZeroMemory(&mod, sizeof(mod));
		SecureZeroMemory(&dataSize, sizeof(dataSize));
		SecureZeroMemory(&dataBlockSize, sizeof(dataBlockSize));
	}
	void SecureWipeData()
	{
		SecureZeroMemory(getRawPtr(), sizeof(*protectedData));
	}

	void swap(Protected& other) noexcept
	{
		using std::swap;
		swap(*this->protectedData, other.protectedData);
		swap(*this->isEncrypted, other.isEncrypted);
	}

	T& operator*() { return get(); }
	const T& operator*() const { return get(); }

	T* const operator->() { return protectedData.operator->(); }
	const T* const operator->() const { return protectedData.operator->(); }

	Protected& operator=(const Protected& rhs)
	{
		swap(*this, rhs);
		return *this;
	}
	Protected& operator=(Protected&& rhs) noexcept
	{
		rhs.swap(*this);
		return *this;
	}

	explicit operator bool() const { return (bool)protectedData; }

	T& get() 
	{	
		ProtectMemory(false);
		return *protectedData; 
	}
	const T& data() const { return *protectedData; }
	void assign(T *obj)
	{
		protectedData = std::make_unique<T>(*obj);
		SecureZeroMemory(obj, sizeof(obj));
	}
	bool empty() const { return *this->operator bool(); }

private:
	T* getRawPtr() { return &(*protectedData); }

	std::unique_ptr<T> protectedData;
	bool isEncrypted = false;
};

template <class T>
void swap(Protected<T>& lhs, Protected<T>& rhs) noexcept
{
	lhs.swap(rhs);
}