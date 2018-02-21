#include "HashRule.hpp"
#include "SecPolicy.hpp"
#include "AppSecPolicy.hpp"
#pragma once

namespace AppSecPolicy
{
	class RuleConsumer
	{
	public:
		explicit RuleConsumer(bool updateRules) : hashRule(updateRules)
		{
			consumerCount++; 
		}

		void ConsumeRules()
		{
			bool rulesLeft;
			RuleAction ruleAction;
			moodycamel::ConsumerToken ruleQueueCtok(SecPolicy::ruleQueue);

			do
			{
				rulesLeft = SecPolicy::fileCheckingNotDone;
				while (SecPolicy::ruleQueue.try_dequeue(ruleQueueCtok, ruleAction))
				{
					rulesLeft = true;

					if (std::get<MOD_TYPE>(ruleAction) == ModificationType::CREATED)
						hashRule.CreateNewHashRule(std::get<RULE_DATA>(ruleAction));

					else if (std::get<MOD_TYPE>(ruleAction) == ModificationType::SWITCHED)
						hashRule.SwitchRule(std::get<FILE_SIZE>(ruleAction),
							std::get<RULE_DATA>(ruleAction));

					else if (std::get<MOD_TYPE>(ruleAction) == ModificationType::UPDATED)
						hashRule.CheckIfRuleOutdated(std::get<FILE_SIZE>(ruleAction),
							std::get<RULE_DATA>(ruleAction));
				}
			} while (rulesLeft || SecPolicy::doneConsumers.fetch_add(1, std::memory_order_acq_rel) + 1 == consumerCount);
		
			SecPolicy::doneConsumers++;
		}
		void RemoveRules()
		{
			RuleAction ruleAction;
			moodycamel::ConsumerToken ruleQueueCtok(SecPolicy::ruleQueue);

			while (SecPolicy::ruleQueue.try_dequeue(ruleQueueCtok, ruleAction))
			{
				if (std::get<MOD_TYPE>(ruleAction) == ModificationType::REMOVED)
					hashRule.RemoveRule(std::get<RULE_GUID>(*std::get<RULE_DATA>(ruleAction)),
						std::get<SEC_OPTION>(*std::get<RULE_DATA>(ruleAction)));
			}
		}
		void CheckRules()
		{
			bool rulesLeft;
			RuleData ruleData;
			const moodycamel::ConsumerToken ruleCheckCtok(SecPolicy::ruleCheckQueue);

			do
			{
				rulesLeft = SecPolicy::doneProducers.load(std::memory_order_acquire) != SecPolicy::producerCount;
				while (SecPolicy::ruleCheckQueue.try_dequeue(ruleData))
				{
					hashRule.CheckRuleIntegrity(ruleData);
				}
			} while (rulesLeft || SecPolicy::doneConsumers.fetch_add(1, std::memory_order_acq_rel) + 1 == consumerCount);

			SecPolicy::doneConsumers++;
		}

	private:
		HashRule hashRule;
		static std::atomic_uint consumerCount;
	};

	std::atomic_uint RuleConsumer::consumerCount = 0;
}