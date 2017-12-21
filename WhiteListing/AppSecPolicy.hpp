#include <vector>
#include <string>
#include <tuple>
#include <memory>
#pragma once

namespace AppSecPolicy
{
	const int SEC_OPTION = 0;
	const int RULE_TYPE = 1;
	const int FILE_LOCATION = 2;
	const int RULE_GUID = 3;

	enum class SecOption { BLACKLIST, WHITELIST };
	enum class RuleType { HASHRULE, PATHRULE };
	enum class WriteType { CREATED_RULES, SWITCHED_RULES, REMOVED_RULES };
	enum class RuleFindResult { EXACT_MATCH, DIFF_SEC_OP, DIFF_TYPE, DIFF_OP_AND_TYPE, NO_MATCH };

	typedef std::vector<std::tuple<SecOption, RuleType,
		std::string, std::shared_ptr<std::string>>> RuleData;
}