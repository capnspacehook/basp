#include <filesystem>
#include <utility>
#include <string>
#include <vector>
#include <memory>
#include <tuple>
#pragma once

namespace fs = std::experimental::filesystem;

namespace AppSecPolicy
{
	//RuleData and UserRule access names
	const int SEC_OPTION = 0;
	const int RULE_TYPE = 1;
	const int FILE_LOCATION = 2;
	const int RULE_GUID = 3;
	const int FRIENDLY_NAME = 4;
	const int ITEM_SIZE = 5;
	const int LAST_MODIFIED = 6;
	const int ITEM_DATA = 7;
	const int SHA256_HASH = 8;
	const int MOD_STATUS = 9;

	//FileInfo access names
	const int RULE_PATH = 0;
	const int FILENAME = 1;
	const int EXTENSION = 2;
	const int DATA_SIZE = 3;

	//RuleAction access names
	const int MOD_TYPE = 0;
	const int FILE_SIZE = 1;
	const int RULE_DATA = 2;

	const int AUTHENTICODE_ENABLED = 0;
	const int DEFAULT_LEVEL = 2;
	const int POLCIY_SCOPE = 4;
	const int TRANSPARENT_ENABLED = 6;

	enum class SecOption { BLACKLIST, WHITELIST, REMOVED };
	enum class RuleType { HASHRULE, PATHRULE };
	enum class ModificationType { CREATED, SWITCHED, UPDATED, SKIPPED, REMOVED };
	enum class RuleFindResult { EXACT_MATCH, DIFF_SEC_OP, DIFF_TYPE, 
		DIFF_OP_AND_TYPE,  EXIST_SUBDIR_SAME_OP, EXIST_SUBDIR_DIFF_OP, 
		EXIST_SUBDIR_TO_BE_RM, NO_EXIST_SUBDIR_SAME_OP, 
		NO_EXIST_SUBDIR_DIFF_OP, NO_EXIST_SUBDIR_TO_BE_RM,
		EXIST_PARENT_DIR_SAME_OP, EXIST_PARENT_DIR_DIFF_OP, 
		NO_EXIST_PARENT_DIR_SAME_OP, NO_EXIST_PARENT_DIR_DIFF_OP,
		PARENT_DIR_TO_BE_RM, RM_SUBDIR, REMOVED, NO_MATCH };

	using UserRule = std::tuple<SecOption, RuleType, std::string>;

	using RuleData = std::tuple<SecOption, RuleType, std::string, 
		std::string, std::string, uintmax_t, uintmax_t, 
		std::vector<unsigned char>, std::vector<unsigned char>, 
		ModificationType>;

	using DirInfo = std::pair<fs::path, uintmax_t>;

	using FileInfo = std::tuple<std::string, std::string, std::string, uintmax_t>;

	using RmRuleInfo = std::pair<std::string, SecOption>;

	using RuleDataPtr = std::shared_ptr<RuleData>;

	using RuleAction = std::tuple<ModificationType, uintmax_t,
		RuleDataPtr>;
}