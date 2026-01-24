/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   Copyright (C) 2018-2020 Matt Schatz <genius3000@g3k.solutions>
 *
 * This file is a module for InspIRCd.  InspIRCd is free software: you can
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

/// $ModAuthor: genius3000
/// $ModAuthorMail: genius3000@g3k.solutions
/// $ModDepends: core 4
/// $ModDesc: Provides extban 'b' - Ban list from another channel

/* Helpop Lines for the EXTBANS section
 * Find: '<helpop key="extbans" title="Extended Bans" value="'
 * Place just before the 'j:<channel>' line:
 b:<channel>   Matches users banned in the given channel
               requires the extbanbanlist contrib module).
 */


#include "inspircd.h"
#include "listmode.h"
#include "modules/extban.h"
#include "numerichelper.h"

class ExtBanBanList final
	: public ExtBan::MatchingBase
{
private:
	ChanModeReference& banmode;
	bool& checking;

	static bool IsChannelBanned(User* user, Channel* target, const ListModeBase::ModeList& bans, bool& checking)
	{
		if (checking)
			return false;

		checking = true;
		for (const auto& entry : bans)
		{
			if (target->CheckBan(user, entry.mask))
			{
				checking = false;
				return true;
			}
		}
		checking = false;
		return false;
	}

public:
	ExtBanBanList(Module* Creator, ChanModeReference& moderef, bool& checkingref)
		: MatchingBase(Creator, "banlist", 'b')
		, banmode(moderef)
		, checking(checkingref)
	{
	}

	bool IsMatch(User* user, Channel* /*channel*/, const std::string& text) override
	{
		Channel* target = ServerInstance->Channels.Find(text);
		if (!target)
			return false;

		ListModeBase* banlm = banmode->IsListModeBase();
		const ListModeBase::ModeList* bans = banlm ? banlm->GetList(target) : nullptr;
		if (!bans)
			return false;

		return IsChannelBanned(user, target, *bans, checking);
	}
};

class BanListWatcher final
	: public ModeWatcher
{
	ExtBan::Base& extban;
	ChanModeReference& banmode;

	static bool ExtractTargetChan(const ExtBan::Base& extban, std::string text, std::string& target)
	{
		for (unsigned int depth = 0; depth < 8; ++depth)
		{
			bool inverted;
			std::string name;
			std::string value;
			if (!ExtBan::Parse(text, name, value, inverted))
				return false;

			if (name.size() == 1)
			{
				if (name[0] == extban.GetLetter())
				{
					target = value;
					return true;
				}
			}
			else if (irc::equals(name, extban.GetName()))
			{
				target = value;
				return true;
			}

			text = value;
		}

		return false;
	}

 public:
	BanListWatcher(Module* parent, ExtBan::Base& xb, ChanModeReference& moderef)
		: ModeWatcher(parent, "ban", MODETYPE_CHANNEL)
		, extban(xb)
		, banmode(moderef)
	{
	}

	bool BeforeMode(User* source, User*, Channel* channel, Modes::Change& change) override
	{
		if (!IS_LOCAL(source) || !channel || !change.adding)
			return true;

		std::string targetname;
		if (!ExtractTargetChan(extban, change.param, targetname))
			return true;
		if (!ServerInstance->Channels.IsChannel(targetname))	// Invalid channel name.
		{
			source->WriteNumeric(Numerics::NoSuchChannel(targetname));
			return false;
		}

		Channel* c = ServerInstance->Channels.Find(targetname);
		if (!c)
		{
			source->WriteNumeric(Numerics::NoSuchChannel(targetname));
			return false;
		}

		if (c == channel)
		{
			source->WriteNumeric(ERR_NOSUCHCHANNEL, targetname, "Target channel must be a different channel");
			return false;
		}

		if (banmode->GetLevelRequired(change.adding) > c->GetPrefixValue(source))
		{
			source->WriteNumeric(ERR_CHANOPRIVSNEEDED, targetname, "You must have access to modify the banlist to use it");
			return false;
		}

		return true;
	}
};

class ModuleExtbanBanlist final
	: public Module
{
	ChanModeReference banmode;
	bool checking = false;
	ExtBanBanList extban;
	BanListWatcher watcher;

 public:
	ModuleExtbanBanlist()
		: Module(VF_VENDOR, "Provides the banlist extban which matches users banned in another channel")
		, banmode(this, "ban")
		, extban(this, banmode, checking)
		, watcher(this, extban, banmode)
	{
	}
};

MODULE_INIT(ModuleExtbanBanlist)