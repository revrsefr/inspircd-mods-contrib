/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   Copyright (C) 2025-04-09 02:49:31 
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

/// $ModAuthor: revrsefr mike.chevronnet@gmail.com
/// $ModDesc: Provides the ability to hide whois information from users.
/// $ModConfig: <hidewhois opers="yes" selfview="yes" hide_server="yes" hide_idle="yes" hide_away="yes" hide_geolocation="yes" hide_secure="yes">
/// $ModDepends: core 4

#include "inspircd.h"
#include "modules/whois.h"

class ModuleHideWhois final
	: public Module
	, public Whois::EventListener
	, public Whois::LineEventListener
{
private:
	bool allow_opers;
	bool allow_selfview;
	bool hide_server;
	bool hide_idle;
	bool hide_away;
	bool hide_geolocation;
	bool hide_secure;

	bool ShouldHideFrom(User* source, User* target)
	{
		// Only apply to local users
		if (!IS_LOCAL(target))
			return false;
			
		// If source is an oper and opers can see all
		if (source->IsOper() && allow_opers)
			return false;
			
		// If viewing self and self-view is allowed
		if (source == target && allow_selfview)
			return false;
			
		// Hide information from regular users and from self if selfview is not allowed
		return true;
	}

public:
	ModuleHideWhois()
		: Module(VF_OPTCOMMON, "Provides the ability to hide whois information from users.")
		, Whois::EventListener(this)
		, Whois::LineEventListener(this)
	{
	}

	void ReadConfig(ConfigStatus& status) override
	{
		const auto& tag = ServerInstance->Config->ConfValue("hidewhois");
		
		allow_opers = tag->getBool("opers", true);
		allow_selfview = tag->getBool("selfview", true);
		hide_server = tag->getBool("hide_server", true);
		hide_idle = tag->getBool("hide_idle", true);
		hide_away = tag->getBool("hide_away", true);
		hide_geolocation = tag->getBool("hide_geolocation", true);
		hide_secure = tag->getBool("hide_secure", true);
	}

	void OnWhois(Whois::Context& whois) override
	{
		// We primarily use LineEventListener for filtering
	}

	ModResult OnWhoisLine(Whois::Context& whois, Numeric::Numeric& numeric) override
	{
		User* source = whois.GetSource();
		User* target = whois.GetTarget();
		
		if (!ShouldHideFrom(source, target))
			return MOD_RES_PASSTHRU;
		
		// Process specific numerics
		switch (numeric.GetNumeric())
		{
			case RPL_WHOISUSER: // 311 - Don't hide the basic user information
				return MOD_RES_PASSTHRU;
				
			case RPL_ENDOFWHOIS: // 318 - Don't hide the end of WHOIS
				return MOD_RES_PASSTHRU;
				
			case RPL_WHOISSERVER: // 312
				if (hide_server)
					return MOD_RES_DENY;
				break;
			
			case RPL_WHOISIDLE: // 317
				if (hide_idle)
					return MOD_RES_DENY;
				break;
			
			case RPL_AWAY: // 301
				if (hide_away)
					return MOD_RES_DENY;
				break;
				
			case RPL_WHOISCOUNTRY: // 344
			case RPL_WHOISGATEWAY: // 350
				if (hide_geolocation)
					return MOD_RES_DENY;
				break;
				
			case RPL_WHOISSECURE: // 671 - "is using a secure connection"
				if (hide_secure)
					return MOD_RES_DENY;
				break;
		}
		
		return MOD_RES_PASSTHRU;
	}
};

MODULE_INIT(ModuleHideWhois)
