#include "AppSecPolicy.hpp"
#include "Windows.h"
#include "WinReg.hpp"

#include <string>
#include <vector>
#pragma once

namespace AppSecPolicy
{
	class HashRule
	{
	public:
		explicit HashRule() noexcept = default;
		explicit HashRule(HashRule &other)
		{
			other.swap(*this);
		}
		explicit HashRule(HashRule &&other) noexcept
		{
			other.swap(*this);
		}
		
		void CreateNewHashRule(std::shared_ptr<RuleData>&);

		void UpdateRule(std::shared_ptr<RuleData>&);

		void SwitchRule(std::shared_ptr<RuleData>&);

		void RemoveRule(const std::string &guid,
			SecOption policy);

		void swap(HashRule& other) noexcept
		{
			using std::swap;
			swap(this->guid, other.guid);
			swap(this->description, other.description);
			swap(this->fileVersion, other.fileVersion);
			swap(this->friendlyName, other.friendlyName);
			swap(this->itemData, other.itemData);
			swap(this->itemSize, other.itemSize);
			swap(this->lastModified, other.lastModified);
			swap(this->sha256Hash, other.sha256Hash);
		}
		HashRule& operator=(HashRule rhs)
		{
			rhs.swap(*this);
			return *this;
		}
		HashRule& operator=(HashRule&& rhs) noexcept
		{
			rhs.swap(*this);
			return *this;
		}

	private:
		void EnumFileVersion(const std::string &fileName);
		void EnumFriendlyName(const std::string &fileName);
		inline void EnumCreationTime();
		void HashDigests(const std::string &fileName);
		inline void CreateGUID();
		void WriteToRegistry(const std::string &fileName,
			const AppSecPolicy::SecOption &policy);
		inline bool MakeGUID();
		inline std::vector<BYTE> convertStrToByte(std::string &str) noexcept;

		std::string guid;
		static const std::string fileProps[5];
		std::string description = "";
		std::string fileVersion;
		std::string friendlyName = "";
		static const int hashAlg = 32771;
		std::vector<BYTE> itemData;
		uintmax_t itemSize;
		uintmax_t lastModified;
		static const int shaHashAlg = 32780;
		std::vector<BYTE> sha256Hash;
	};
}