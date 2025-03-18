/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   Copyright (C) 2025 revrsefr
 *
 * This file is part of InspIRCd.  InspIRCd is free software: you can
 * redistribute it and/or modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/// $ModAuthor: reverse mike.chevronnet@gmail.com
/// $ModDesc: IRCv3 Typing Indicator (+draft/typing)
/// $ModDepends: core 4

#include "inspircd.h"

class ModuleIRCv3Typing : public Module
	, public ClientProtocol::MessageTagProvider
{
 private:
	bool ValidateTypingValue(const std::string& tagval)
	{
		return (tagval == "active" || tagval == "paused" || tagval == "done");
	}

 public:
	ModuleIRCv3Typing()
		: Module(VF_COMMON, "Provides +typing and +draft/typing client message tags for typing indications")
		, ClientProtocol::MessageTagProvider(this)
	{
	}

	void ReadConfig(ConfigStatus& status) override
	{
		// No configuration needed
	}

	ModResult OnProcessTag(User* user, const std::string& tagname, std::string& tagvalue) override
	{
		if ((tagname == "+typing" || tagname == "+draft/typing") && !ValidateTypingValue(tagvalue))
			return MOD_RES_DENY;
		return MOD_RES_PASSTHRU;
	}

	void OnClientProtocolPopulateTags(const ClientProtocol::Message& msg, ClientProtocol::TagMap& tags) override
	{
		// Propagate typing tags from client to client
		const User* user = msg.GetSource();
		if (!user || !user->client)
			return;

		const ClientProtocol::TagMap& msgtags = msg.GetTags();
		
		auto typingit = msgtags.find("+typing");
		auto drafttypingit = msgtags.find("+draft/typing");
		
		if (typingit != msgtags.end() && ValidateTypingValue(typingit->second.value))
			tags.emplace("+typing", typingit->second);

		if (drafttypingit != msgtags.end() && ValidateTypingValue(drafttypingit->second.value))
			tags.emplace("+draft/typing", drafttypingit->second);
	}

	void OnUserPostMessage(User* user, const MessageTarget& target, const MessageDetails& details) override
	{
		// No additional processing needed
	}
};

MODULE_INIT(ModuleIRCv3Typing)
