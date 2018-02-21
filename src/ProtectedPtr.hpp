#include "Windows.h"
#include "Wincrypt.h"
#include "include\Crypto++\secblock.h"

#include <string>
#include <memory>

#pragma comment(lib, "crypt32.lib")
#pragma once

namespace Protected_Ptr
{
	//converts data of type T to a byte array, 
	//gets size of data, and returns reference to raw data
	template <class T>
	class PrimitiveSerializer
	{
	public:

		DWORD getSize(const T& obj) const { return sizeof(obj); }
		//return reference to raw data
		T* getRawData(T& obj) const { return &obj; }
		//convert data into byte array
		std::unique_ptr<byte*> serialize(T& obj) const
		{
			const auto size = getSize(obj);
			auto out = std::make_unique<byte*>(new byte[size]);
			std::memcpy(*out, getRawData(obj), size);
			return out;
		}

		bool overwriteOnExit = true;
	};

	class StringSerializer
	{
	public:
		DWORD getSize(const std::string& str) const noexcept { return sizeof(str); }
		std::string* getRawData(std::string& str) const noexcept { return &str; }	
		std::unique_ptr<byte*> serialize(const std::string& str) const
		{
			const auto size = str.size();
			auto out = std::make_unique<byte*>(new byte[size]);
			std::memcpy(*out, str.c_str(), size);
			return out;
		}

		bool overwriteOnExit = true;
	};

	class SecByteBlockSerializer
	{
	public:
		DWORD getSize(const CryptoPP::SecByteBlock& blk) const { return blk.size(); }
		byte* getRawData(CryptoPP::SecByteBlock& blk) const { return blk.data(); }
		std::unique_ptr<byte*> serialize(CryptoPP::SecByteBlock& blk) const
		{
			return std::make_unique<byte*>(getRawData(blk));
		}

		bool overwriteOnExit = false;
	};

	template <class T, class S = PrimitiveSerializer<T>>
	class ProtectedPtr
	{
	public:
		ProtectedPtr() = default;
		explicit ProtectedPtr(T &obj) { assign(obj); }
		ProtectedPtr(ProtectedPtr &rhs) noexcept : protectedData(nullptr)
		{
			//make sure data is encrypted
			ProtectMemory(true);
			rhs.ProtectMemory(true);

			rhs.swap(*this);
		}
		ProtectedPtr(ProtectedPtr &&rhs) noexcept : protectedData(nullptr)
		{
			//make sure data is encrypted
			ProtectMemory(true);
			rhs.ProtectMemory(true);

			rhs.swap(*this);
		}
		~ProtectedPtr()
		{
			ProtectMemory(false);
			SecureWipeData();
		}

		bool IsProtected() const noexcept { return isEncrypted };
		void ProtectMemory(bool encrypt)
		{
			if (protectedData)
			{ 
				DWORD mod;
				DWORD dataBlockSize;
				DWORD dataSize = size();

				if (dataSize > 0)
				{
					//CryptProtectMemory requires data to be a multiple of its block size
					mod = dataSize % CRYPTPROTECTMEMORY_BLOCK_SIZE;

					if (mod != 0)
						dataBlockSize = dataSize + (CRYPTPROTECTMEMORY_BLOCK_SIZE - mod);

					else
						dataBlockSize = dataSize;

					if (encrypt && !isEncrypted)
					{
						isEncrypted = true;
						if (!CryptProtectMemory(getRawPtr(), dataBlockSize,
							CRYPTPROTECTMEMORY_SAME_PROCESS))
						{
							cerr << "CryptProtectMemory failed: " << GetLastError() << '\n';
						}
					}
					else if (!encrypt && isEncrypted)
					{
						isEncrypted = false;
						if (!CryptUnprotectMemory(getRawPtr(), dataBlockSize,
							CRYPTPROTECTMEMORY_SAME_PROCESS))
						{
							cerr << "CryptProtectMemory failed: " << GetLastError() << '\n';
						}
					}

					SecureZeroMemory(&mod, sizeof(mod));
					SecureZeroMemory(&dataSize, sizeof(dataSize));
					SecureZeroMemory(&dataBlockSize, sizeof(dataBlockSize));
				}
			}
		}
		void SecureWipeData()
		{
			if (serializer.overwriteOnExit)
				SecureZeroMemory(getRawPtr(), size());
		}

		void swap(ProtectedPtr& other) noexcept
		{
			using std::swap;
			swap(*this->protectedData, other.protectedData);
			swap(*this->isEncrypted, other.isEncrypted);
			swap(*this->overwriteOnExit, other.overwriteOnExit);
		}

		T& operator*()
		{
			ProtectMemory(false);
			return *protectedData;
		}
		const T& operator*() const
		{
			ProtectMemory(false);
			return *protectedData;
		}

		T* const operator->()
		{
			ProtectMemory(false);
			return protectedData.operator->();
		}
		const T* const operator->() const
		{
			ProtectMemory(false);
			return protectedData.operator->();
		}

		ProtectedPtr& operator=(ProtectedPtr rhs) noexcept
		{
			//make sure data is encrypted
			ProtectMemory(true);
			other.ProtectMemory(true);

			rhs.swap(*this);
			return *this;
		}
		ProtectedPtr& operator=(ProtectedPtr &&rhs) noexcept
		{
			//make sure data is encrypted
			ProtectMemory(true);
			other.ProtectMemory(true);

			rhs.swap(*this);
			return *this;
		}
		
		//constant time comparison 
		bool operator==(ProtectedPtr &rhs)
		{
			if (serializer.size() != rhs.serializer.size())
				return false;

			volatile auto thisData = serializeData();
			ProtectMemory(true);

			volatile auto otherData = rhs.serializeData();
			rhs.ProtectMemory(true);

			volatile byte result = 0;
			for (int i = 0; i < sizeof(*protectedData); i++)
			{
				result |= thisData[i] ^ otherData[i];
				//securely wipe unencrypted copies of data
				thisData[i] = 0;
				otherData[i] = 0;
			}

			return result == 0;
		}
		bool operator!=(ProtectedPtr &rhs)
		{
			return !(*this == rhs);
		}

		explicit operator bool() const { return (bool)protectedData; }

		T& get() { return this->operator*(); }
		const T& data() const { return this->operator*(); }
		void assign(T &obj)
		{
			//if protectedData is already pointing to something,
			//securely overwrite and delete it
			if (protectedData)
			{
				ProtectMemory(false);
				SecureWipeData();
				protectedData.release();
			}

			//point to copy of data, encrypt it, and overwrite
			//original unencrypted data
			protectedData = std::make_unique<T>(obj);
			ProtectMemory(true);
			SecureZeroMemory(&obj, sizeof(obj));
		}
		bool empty() const { return (bool)*this; }

	private:
		//returns reference to data pointed to
		void* getRawPtr() { return serializer.getRawData(*protectedData); }
		std::unique_ptr<byte*> serializeData()
		{
			ProtectMemory(false);
			return serializer.serialize(*protectedData);
		}
		DWORD size() const { return serializer.getSize(*protectedData); }

		S serializer;
		std::unique_ptr<T> protectedData;
		bool isEncrypted = false;
	};

	template <class T, class S = PrimitiveSerializer<T>>
	void swap(ProtectedPtr<T, S>& lhs, ProtectedPtr<T, S>& rhs) noexcept { lhs.swap(rhs); }

} //namespace Protected_Ptr