#include "SecPolicy.hpp"
#include "AppSecPolicy.hpp"
#include "DataFileManger.hpp"

#pragma once

namespace AppSecPolicy
{
	class RuleConsumer;

	class RuleProducer
	{
	public:
		RuleProducer() noexcept { SecPolicy::producerCount++; }
		
		void ProduceRules()
		{
			fs::path dir;
			DirInfo dirInfo;
			std::string fileName;
			std::string extension;
			
			const moodycamel::ProducerToken dirPtok(SecPolicy::dirItQueue);
			moodycamel::ConsumerToken dirCtok(SecPolicy::dirItQueue);
			const moodycamel::ProducerToken fileCheckPtok(SecPolicy::fileCheckQueue);

			while (SecPolicy::dirItQueue.try_dequeue(dirCtok, dirInfo))
			{
				dir = std::move(dirInfo.first);
				uintmax_t fileSize = dirInfo.second;
				for (const auto &currFile : fs::directory_iterator(dir))
				{
					if (fs::exists(currFile))
					{
						if (fs::is_directory(currFile))
							SecPolicy::dirItQueue.enqueue(dirPtok,
								std::make_pair(currFile, fileSize));

						else
						{
							fileSize = fs::file_size(currFile);
							if (fileSize && fs::is_regular_file(currFile))
							{
								extension = currFile.path().extension().string();

								if (!extension.empty())
								{
									fileName = currFile.path().string();
									std::transform(fileName.begin(), fileName.end(),
										fileName.begin(), tolower);

									extension = extension.substr(1, extension.length());
									std::transform(extension.begin(), extension.end(),
										extension.begin(), toupper);

									SecPolicy::fileCheckQueue.enqueue(fileCheckPtok,
										std::make_tuple(fileName, extension, fileSize));
								}
							}
						}
					}
				}
			}

			SecPolicy::doneProducers++;
		}

		void ProcessFile(const fs::path &file, const uintmax_t &fileSize) const
		{
			if (fileSize && fs::is_regular_file(file))
			{
				std::string extension = file.extension().string();

				if (!extension.empty())
				{
					std::string fileName = file.string();
					std::transform(fileName.begin(), fileName.end(),
						fileName.begin(), tolower);

					extension = extension.substr(1, extension.length());
					std::transform(extension.begin(), extension.end(),
						extension.begin(), toupper);

					SecPolicy::fileCheckQueue.enqueue(
						std::make_tuple(fileName, extension, fileSize));
				}
			}

			SecPolicy::doneProducers++;
		}

		void ConvertRules()
		{
			std::string temp;
			RuleData ruleData;
			moodycamel::ConsumerToken ruleStrCtok(SecPolicy::ruleStringQueue);
			const moodycamel::ProducerToken ruleCheckPtoc(SecPolicy::ruleCheckQueue);

			while (SecPolicy::ruleStringQueue.try_dequeue(ruleStrCtok, temp))
			{
				ruleData = DataFileManager::StringToRuleData(temp);
				SecPolicy::ruleCheckQueue.enqueue(ruleCheckPtoc, move(ruleData));
			}

			SecPolicy::doneProducers++;
		}
	};
}