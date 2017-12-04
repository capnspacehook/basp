#include <vector>
#include <string>
#include <tuple>
#pragma once

namespace AppSecPolicy
{
	const int SEC_OPTION = 0;
	const int RULE_TYPE = 1;
	const int FILE_LOCATION = 2;
	const int RULE_GUID = 3;

	enum class SecOptions { BLACKLIST, WHITELIST };
	enum class RuleType { HASHRULE, PATHRULE };

	typedef std::vector<std::tuple< SecOptions, RuleType,
		std::string, std::string*>> RuleData;
}
