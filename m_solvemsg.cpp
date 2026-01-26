/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   Copyright (C) 2015-2016 Sadie Powell <sadie@witchery.services>
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

/// $ModAuthor: Sadie Powell - Updated to v4 by reverse mike.chevronnet@gmail.com
/// $ModAuthorMail: sadie@witchery.services
/// $ModConfig: <solvemsg chanmsg="no" usermsg="yes" exemptregistered="yes" warntime="60s" warnintro="..." warnquestion="..." warnhowto="...">
/// $ModDepends: core 4
/// $ModDesc: Requires users to solve a basic maths problem before messaging others.


#include "inspircd.h"
#include "extension.h"
#include "modules/account.h"

static std::string ReplaceAll(std::string value, const std::string& needle, const std::string& replacement)
{
	if (needle.empty())
		return value;

	size_t pos = 0;
	while ((pos = value.find(needle, pos)) != std::string::npos)
	{
		value.replace(pos, needle.size(), replacement);
		pos += replacement.size();
	}
	return value;
}

struct Problem final
{
	int first;
	int second;
	time_t nextwarning;
};

class CommandSolve final
	: public SplitCommand
{
 private:
	SimpleExtItem<Problem>& ext;

 public:
	CommandSolve(Module* Creator, SimpleExtItem<Problem>& Ext)
		: SplitCommand(Creator, "SOLVE", 1, 1)
		, ext(Ext)
	{
	}

	CmdResult HandleLocal(LocalUser* user, const Params& parameters) override
	{
		Problem* problem = ext.Get(user);
		if (!problem)
		{
			user->WriteNotice("** You have already solved your problem!");
			return CmdResult::FAILURE;
		}

		int result = ConvToNum<int>(parameters[0]);
		if (result != (problem->first + problem->second))
		{
			user->WriteNotice(INSP_FORMAT("*** {} is not the correct answer.", parameters[0]));
			user->CommandFloodPenalty += 10000;
			return CmdResult::FAILURE;
		}

		ext.Unset(user);
		user->WriteNotice(INSP_FORMAT("*** {} is the correct answer!", parameters[0]));
		return CmdResult::SUCCESS;
	}
};

class ModuleSolveMessage final
	: public Module
{
 private:
	SimpleExtItem<Problem> ext;
	CommandSolve cmd;
	Account::API accountapi;
	bool chanmsg;
	bool usermsg;
	bool exemptregistered;
	time_t warntime;
	std::string warnintro;
	std::string warnquestion;
	std::string warnhowto;

 public:
	ModuleSolveMessage()
		: Module(VF_VENDOR, "Requires users to solve a basic maths problem before messaging others.")
		, ext(this, "solve-message", ExtensionType::USER)
		, cmd(this, ext)
		, accountapi(this)
	{
	}

	void ReadConfig(ConfigStatus& status) override
	{
		const auto& tag = ServerInstance->Config->ConfValue("solvemsg");
		chanmsg = tag->getBool("chanmsg", false);
		usermsg = tag->getBool("usermsg", true);
		exemptregistered = tag->getBool("exemptregistered", true);
		warntime = tag->getDuration("warntime", 60, 1);

		warnintro = tag->getString("warnintro", "*** Before you can send messages you must solve the following problem:");
		warnquestion = tag->getString("warnquestion", "*** What is {problem}?");
		warnhowto = tag->getString("warnhowto", "*** You can enter your answer using /QUOTE SOLVE <answer>");
	}

	void OnUserPostInit(LocalUser* user) override
	{
		Problem problem;
		problem.first = ServerInstance->GenRandomInt(9);
		problem.second = ServerInstance->GenRandomInt(9);
		problem.nextwarning = 0;
		ext.Set(user, problem);
	}

	ModResult OnUserPreMessage(User* user, MessageTarget& msgtarget, MessageDetails& details) override
	{
		LocalUser* source = IS_LOCAL(user);
		if (!source)
			return MOD_RES_PASSTHRU;

		const auto& klass = source->GetClass();
		if (klass && !klass->config->getBool("usesolvemsg", true))
			return MOD_RES_PASSTHRU; // Exempt by connect class.

		std::string_view ctcpname;
		if (details.IsCTCP(ctcpname) && !irc::equals(ctcpname, "ACTION"))
			return MOD_RES_PASSTHRU; // Exempt non-ACTION CTCPs.

		if (exemptregistered)
		{
			if (accountapi && accountapi->GetAccountName(user))
				return MOD_RES_PASSTHRU; // Exempt logged in users.
		}

		switch (msgtarget.type)
		{
			case MessageTarget::TYPE_USER:
			{
				if (!usermsg)
					return MOD_RES_PASSTHRU; // Not enabled.

				User* target = msgtarget.Get<User>();
				if (target->server->IsService())
					return MOD_RES_PASSTHRU; // Allow messaging ulines.

				break;
			}

			case MessageTarget::TYPE_CHANNEL:
			{
				if (!chanmsg)
					return MOD_RES_PASSTHRU; // Not enabled.

				Channel* target = msgtarget.Get<Channel>();
				if (target->GetPrefixValue(user) >= VOICE_VALUE)
					return MOD_RES_PASSTHRU; // Exempt users with a status rank.
				break;
			}

			case MessageTarget::TYPE_SERVER:
				return MOD_RES_PASSTHRU; // Only opers can do this.
		}

		Problem* problem = ext.Get(user);
		if (!problem)
			return MOD_RES_PASSTHRU;

		if (problem->nextwarning > ServerInstance->Time())
			return MOD_RES_DENY;

		user->WriteNotice(warnintro);
		user->WriteNotice(ReplaceAll(warnquestion, "{problem}", INSP_FORMAT("{} + {}", problem->first, problem->second)));
		user->WriteNotice(warnhowto);
		problem->nextwarning = ServerInstance->Time() + warntime;
		return MOD_RES_DENY;
	}
};

MODULE_INIT(ModuleSolveMessage)