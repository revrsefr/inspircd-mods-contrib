/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   Copyright (C) 2024 reverse
 *
 * This file contains a third-party module for InspIRCd. You can
 * redistribute it and/or modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.

 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/// $ModAuthor: reverse <mike.chevronnet@gmail.com>
/// $ModDesc: Adds the port and connect class of the user to WHOIS for operators only.
/// $ModDepends: core 4

#include "inspircd.h"
#include "modules/whois.h"
#include "extension.h"

class ModuleWhoisPort final
	: public Module
	, public Whois::EventListener
{
public:
	StringExtItem portext;
	StringExtItem classext;
	ModuleWhoisPort()
		: Module(VF_OPTCOMMON, "Adds the port and connect class of the user to WHOIS for operators only.")
		, Whois::EventListener(this)
		, portext(this, "whoisport", ExtensionType::USER, true) // synced
		, classext(this, "whoisclass", ExtensionType::USER, true) // synced
	{
	}

	void OnUserConnect(LocalUser* user) override
	{
		portext.Set(user, ConvToStr(user->server_sa.port()), true);
		const auto& klass = user->GetClass();
		if (klass)
			classext.Set(user, klass->GetName(), true);
	}

	void OnChangeConnectClass(LocalUser* user, const std::shared_ptr<ConnectClass>& klass, bool) override
	{
		if (klass)
			classext.Set(user, klass->GetName(), true);
		else
			classext.Unset(user);
	}

	void OnWhois(Whois::Context& whois) override
	{
		User* source = whois.GetSource();
		User* target = whois.GetTarget();

		// Only show information if the requesting user (source) is an IRC operator with users/auspex privs.
		if (!source->IsOper() || !source->HasPrivPermission("users/auspex"))
			return;

		// Get data from synced extensions (works for local and remote users).
		const std::string* portstr = portext.Get(target);
		const std::string* classstr = classext.Get(target);

		if (!portstr || portstr->empty())
			return;

		std::string line = "is using port " + *portstr;
		if (classstr && !classstr->empty())
			line += " and connect class: " + *classstr;

		whois.SendLine(RPL_WHOISSPECIAL, line);
	}
};

MODULE_INIT(ModuleWhoisPort)

