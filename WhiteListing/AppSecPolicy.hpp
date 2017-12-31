#include <string>
#include <vector>
#include <tuple>
#pragma once

namespace AppSecPolicy
{
	const int SEC_OPTION = 0;
	const int RULE_TYPE = 1;
	const int FILE_LOCATION = 2;
	const int RULE_GUID = 3;
	const int FRIENDLY_NAME = 4;
	const int ITEM_SIZE = 5;
	const int LAST_MODIFIED = 6;
	const int ITEM_DATA = 7;
	const int SHA256_HASH = 8;

	const int AUTHENTICODE_ENABLED = 0;
	const int DEFAULT_LEVEL = 2;
	const int POLCIY_SCOPE = 4;
	const int TRANSPARENT_ENABLED = 6;

	const int MD5_HASH_LENGTH = 16;
	const int SHA_HASH_LENGTH = 32;

	enum class SecOption { BLACKLIST, WHITELIST, REMOVED };
	enum class RuleType { HASHRULE, PATHRULE };
	enum class WriteType { CREATED_RULES, SWITCHED_RULES };
	enum class RuleFindResult { EXACT_MATCH, DIFF_SEC_OP, DIFF_TYPE, 
		DIFF_OP_AND_TYPE, SUBDIRECTORY, SUBDIR_DIFF_SEC_OP, NO_MATCH };

	typedef std::tuple<SecOption, RuleType, std::string> UserRule;

	typedef std::tuple<SecOption, RuleType, std::string, std::string, std::string,
		uintmax_t, uintmax_t, std::vector<unsigned char>, std::vector<unsigned char>> RuleData;
}