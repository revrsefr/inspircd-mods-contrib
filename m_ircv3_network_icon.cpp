/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   Copyright (C) 2026 Jean Chevronnet <mike.chevronnet@gmail.com>
 *
 * This file contains a third party module for InspIRCd.  You can
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

/// $ModAuthor: reverse <mike.chevronnet@gmail.com>
/// $ModDepends: core 4
/// $ModDesc: Provides the IRCv3 draft/network-icon ISUPPORT token (draft/ICON).

#include "inspircd.h"
#include "modules/isupport.h"

class ModuleIRCv3NetworkIcon final
	: public Module
	, public ISupport::EventListener
{
private:
	std::string iconurl;

public:
	ModuleIRCv3NetworkIcon()
		: Module(VF_VENDOR, "Provides the IRCv3 draft/network-icon ISUPPORT token.")
		, ISupport::EventListener(this)
	{
	}

	void ReadConfig(ConfigStatus& status) override
	{
		const auto& tag = ServerInstance->Config->ConfValue("networkicon");
		const auto url = tag->getString("url");

		if (url.empty())
			throw ModuleException(this, "You have loaded the ircv3_network_icon module but not configured <networkicon:url>!");

		iconurl = url;
	}

	void OnBuildISupport(ISupport::TokenMap& tokens) override
	{
		if (iconurl.empty())
			return;

		tokens["draft/ICON"] = iconurl;
	}
};

MODULE_INIT(ModuleIRCv3NetworkIcon)
