/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   Copyright (C) 2025 InspIRCd Contributors
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


#include "inspircd.h"
#include "extension.h"
#include "modules/cap.h"

enum
{
	// From RFC 1459.
	RPL_NAMREPLY = 353,
	RPL_ENDOFNAMES = 366,
};

namespace
{
	struct PendingNames final
	{
		std::set<std::string, irc::insensitive_swo> channels;
	};

	class NoImplicitNamesCap final
		: public Cap::Capability
	{
	public:
		explicit NoImplicitNamesCap(Module* mod)
			: Cap::Capability(mod, "draft/no-implicit-names")
		{
		}
	};
}

class ModuleIRCv3NoImplicitNames final
	: public Module
{
private:
	NoImplicitNamesCap cap;
	SimpleExtItem<PendingNames> pending;

	static bool GetNamesChannel(const Numeric::Numeric& numeric, std::string& channel)
	{
		switch (numeric.GetNumeric())
		{
			case RPL_NAMREPLY:
			{
				const auto& params = numeric.GetParams();
				if (params.size() < 2)
					return false;
				channel = params[1];
				return true;
			}
			case RPL_ENDOFNAMES:
			{
				const auto& params = numeric.GetParams();
				if (params.empty())
					return false;
				channel = params[0];
				return true;
			}
			default:
				return false;
		}
	}

public:
	ModuleIRCv3NoImplicitNames()
		: Module(VF_VENDOR, "Provides the IRCv3 draft/no-implicit-names client capability.")
		, cap(this)
		, pending(this, "ircv3-no-implicit-names-pending", ExtensionType::USER)
	{
	}

	void Prioritize() override
	{
		// Ensure we get early access to NAMES numerics so we can suppress them.
		ServerInstance->Modules.SetPriority(this, I_OnNumeric, PRIORITY_FIRST);
	}

	void OnUserDisconnect(LocalUser* user) override
	{
		pending.Unset(user);
	}

	void OnUserJoin(Membership* memb, bool bursting, bool, CUList&) override
	{
		if (bursting)
			return;

		LocalUser* const localuser = IS_LOCAL(memb->user);
		if (!localuser)
			return;

		if (!cap.IsEnabled(localuser))
			return;

		pending.GetRef(localuser).channels.insert(memb->chan->name);
	}

	ModResult OnNumeric(User* user, const Numeric::Numeric& numeric) override
	{
		LocalUser* const localuser = IS_LOCAL(user);
		if (!localuser)
			return MOD_RES_PASSTHRU;

		if (!cap.IsEnabled(localuser))
			return MOD_RES_PASSTHRU;

		std::string channel;
		if (!GetNamesChannel(numeric, channel))
			return MOD_RES_PASSTHRU;

		auto* pend = pending.Get(localuser);
		if (!pend)
			return MOD_RES_PASSTHRU;

		auto it = pend->channels.find(channel);
		if (it == pend->channels.end())
			return MOD_RES_PASSTHRU;

		// Suppress implicit NAMES replies after JOIN when draft/no-implicit-names is negotiated.
		if (numeric.GetNumeric() == RPL_ENDOFNAMES)
		{
			pend->channels.erase(it);
			if (pend->channels.empty())
				pending.Unset(localuser);
		}

		return MOD_RES_DENY;
	}
};

MODULE_INIT(ModuleIRCv3NoImplicitNames)
