/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   Copyright (C) 2014 Attila Molnar <attilamolnar@hush.com>
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

/// $ModAuthor: Attila Molnar updated by reverse for v4
/// $ModAuthorMail: attilamolnar@hush.com
/// $ModConfig: <extbanredirect char="d">
/// $ModDepends: core 4
/// $ModDesc: Provide extended ban <extbanchar>:<chan>:<mask> to redirect users to another channel


#include "inspircd.h"
#include "listmode.h"
#include "modules/extban.h"

enum
{
	// From UnrealIRCd
	ERR_LINKCHANNEL = 470,
	// From m_banredirect
	ERR_REDIRECT = 690
};

class BanWatcher : public ModeWatcher
{
 public:
	ExtBan::Base& extban;

	BanWatcher(Module* parent, ExtBan::Base& xb)
		: ModeWatcher(parent, "ban", MODETYPE_CHANNEL)
		, extban(xb)
	{
	}

	bool IsExtBanRedirect(const std::string& mask, std::string& value, bool& inverted)
	{
		std::string name;
		if (!ExtBan::Parse(mask, name, value, inverted))
			return false;

		if (inverted)
			return false;

		if (name.size() == 1)
			return name[0] == extban.GetLetter();
		return irc::equals(name, extban.GetName());
	}

	bool BeforeMode(User* source, User*, Channel* channel, Modes::Change& change) override
	{
		if (!IS_LOCAL(source) || !channel || !change.adding)
			return true;

		std::string value;
		bool inverted;
		if (!IsExtBanRedirect(change.param, value, inverted))
			return true;

		const std::string::size_type p = value.find(':');
		if (p == std::string::npos)
		{
			source->WriteNumeric(ERR_REDIRECT, INSP_FORMAT("Extban redirect \"{}\" is invalid. Format: <extban>:<chan>:<mask>", change.param));
			return false;
		}

		const std::string targetname(value, 0, p);
		if (!ServerInstance->Channels.IsChannel(targetname))
		{
			source->WriteNumeric(ERR_NOSUCHCHANNEL, channel->name, INSP_FORMAT("Invalid channel name in redirection ({})", targetname));
			return false;
		}

		Channel* const targetchan = ServerInstance->Channels.Find(targetname);
		if (!targetchan)
		{
			source->WriteNumeric(ERR_NOSUCHCHANNEL, channel->name, INSP_FORMAT("Target channel {} must exist to be set as a redirect.", targetname));
			return false;
		}

		if (targetchan == channel)
		{
			source->WriteNumeric(ERR_NOSUCHCHANNEL, channel->name, "You cannot set a ban redirection to the channel the ban is on");
			return false;
		}

		if (targetchan->GetPrefixValue(source) < OP_VALUE)
		{
			source->WriteNumeric(ERR_CHANOPRIVSNEEDED, channel->name, INSP_FORMAT("You must be opped on {} to set it as a redirect.", targetname));
			return false;
		}

		return true;
	}
};

class ExtBanRedirect final
	: public ExtBan::MatchingBase
{
	static bool CheckSimpleBan(User* user, const std::string& mask)
	{
		const auto at = mask.find('@');
		if (at == std::string::npos)
			return false;

		const std::string prefix(mask, 0, at);
		if (!InspIRCd::Match(user->nick + "!" + user->GetDisplayedUser(), prefix) &&
			!InspIRCd::Match(user->nick + "!" + user->GetRealUser(), prefix))
		{
			return false;
		}

		const std::string suffix(mask, at + 1);
		return InspIRCd::Match(user->GetRealHost(), suffix) ||
			InspIRCd::Match(user->GetDisplayedHost(), suffix) ||
			InspIRCd::MatchCIDR(user->GetAddress(), suffix);
	}

public:
	ExtBanRedirect(Module* Creator)
		: MatchingBase(Creator, "redirect", 'd')
	{
	}

	void Canonicalize(std::string& text) override
	{
		const auto p = text.find(':');
		if (p == std::string::npos)
			return;

		std::string chan(text, 0, p);
		std::string mask(text, p + 1);
		ModeParser::CleanMask(mask);
		text.assign(chan).append(":").append(mask);
	}

	bool IsMatch(User* user, Channel* channel, const std::string& text) override
	{
		const auto p = text.find(':');
		if (p == std::string::npos)
			return false;

		const std::string mask(text, p + 1);
		return CheckSimpleBan(user, mask);
	}
};

class ModuleExtBanRedirect : public Module
{
	ChanModeReference limitmode;
	ChanModeReference limitredirect;
	ExtBanRedirect extban;
	BanWatcher banwatcher;
	bool active;

 public:
	ModuleExtBanRedirect()
		: Module(VF_VENDOR, "Provide extended ban <extbanchar>:<chan>:<mask> to redirect users to another channel")
		, limitmode(this, "limit")
		, limitredirect(this, "redirect")
		, extban(this)
		, banwatcher(this, extban)
		, active(false)
	{
	}

	void ReadConfig(ConfigStatus&) override
	{
		// The extban letter is configured via <extbans redirect="...">.
		// This tag is kept for compatibility with older configs.
		const auto& tag = ServerInstance->Config->ConfValue("extbanredirect");
		const auto confletter = tag->getString("char", "", 1, 1);
		if (!confletter.empty() && confletter[0] != extban.GetLetter())
			ServerInstance->Logs.Debug(MODNAME, "Ignoring <extbanredirect:char>; use <extbans redirect=\"{}\"> instead.", confletter[0]);
	}

	ModResult OnCheckBan(User* user, Channel* chan, const std::string& mask) override
	{
		LocalUser* localuser = IS_LOCAL(user);

		if (active || !localuser)
			return MOD_RES_PASSTHRU;

		std::string value;
		bool inverted;
		if (!banwatcher.IsExtBanRedirect(mask, value, inverted))
			return MOD_RES_PASSTHRU;

		if (!extban.IsMatch(localuser, chan, value))
			return MOD_RES_PASSTHRU;

		std::string::size_type p = value.find(':');
		if (p == std::string::npos)
			return MOD_RES_PASSTHRU;

		const std::string targetname = value.substr(0, p);
		Channel* const target = ServerInstance->Channels.Find(targetname);
		if (target && target->IsModeSet(limitmode))
		{
			if (target->IsModeSet(limitredirect) && target->GetUsers().size() >= ConvToNum<size_t>(target->GetModeParameter(limitmode)))
			{
				// The core will send "You're banned"
				return MOD_RES_DENY;
			}
		}

		// Ok to redirect
		// The core will send "You're banned"
		localuser->WriteNumeric(ERR_LINKCHANNEL, chan->name, targetname, "You are banned from this channel, so you are automatically being transferred to the redirected channel.");
		active = true;
		Channel::JoinUser(localuser, targetname);
		active = false;

		return MOD_RES_DENY;
	}
};

MODULE_INIT(ModuleExtBanRedirect)