#include "AppSecPolicy.hpp"

#include <string_view>
#pragma once

namespace AppSecPolicy
{
	class HashRule
	{
	public:
		explicit HashRule(bool update) noexcept : updateRules(update) {}
		~HashRule() = default;
		HashRule(HashRule&) = default;
		HashRule(HashRule&&) = default;
		
		void CreateNewHashRule(RuleDataPtr&);
		bool CheckIfRuleOutdated(const uintmax_t&, 
			RuleDataPtr&, bool = true);
		void SwitchRule(const uintmax_t&, RuleDataPtr&);
		void RemoveRule(const std::string &guid,
			SecOption policy) const;
		void CheckRuleIntegrity(const RuleData&);

		HashRule& operator=(HashRule&) = default;
		HashRule& operator=(HashRule&&) = default;

	private:
		void UpdateRule(const uintmax_t&, RuleData&, bool);
		void EnumFileVersion(const std::string_view &fileName);
		void EnumFriendlyName(const std::string_view &fileName);
		inline void EnumCreationTime() noexcept;
		void HashDigests(const std::string_view &fileName);
		inline void CreateGUID();
		void WriteToRegistry(const std::string_view &fileName,
			SecOption policy);
		inline bool MakeGUID();
		inline std::vector<BYTE> convertStrToByte(std::string &str) noexcept;

		bool updateRules = false;
		std::string guid;
		static const std::string fileProps[5];
		std::string description;
		std::string fileVersion;
		std::string friendlyName;
		static constexpr int hashAlg = 32771;
		std::vector<BYTE> itemData;
		uintmax_t itemSize;
		uintmax_t lastModified;
		static constexpr int shaHashAlg = 32780;
		std::vector<BYTE> sha256Hash;
	};
}