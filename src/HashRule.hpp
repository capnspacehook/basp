#include "AppSecPolicy.hpp"
#include "Windows.h"
#pragma once

namespace AppSecPolicy
{
	class HashRule
	{
	public:
		HashRule() {};
		explicit HashRule(HashRule &other)
		{
			other.swap(*this);
		}
		explicit HashRule(HashRule &&other) noexcept
		{
			other.swap(*this);
		}
		
		void CreateNewHashRule(RuleDataPtr&);
		bool CheckIfRuleOutdated(const uintmax_t&, 
			RuleDataPtr&, bool = true);
		void SwitchRule(const uintmax_t&, RuleDataPtr&);
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
		void UpdateRule(const uintmax_t&, RuleData&, bool);
		void EnumFileVersion(const std::string &fileName);
		void EnumFriendlyName(const std::string &fileName);
		inline void EnumCreationTime();
		void HashDigests(const std::string &fileName);
		inline void CreateGUID();
		void WriteToRegistry(const std::string &fileName,
			const SecOption &policy);
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