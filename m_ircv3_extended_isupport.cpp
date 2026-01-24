/*
 * InspIRCd -- Internet Relay Chat Daemon - reverse mike.chevronnet@gmail.com
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

 * raw test log:

 * [01/24 12:18:32]  -> server.com @label=0358 CAP REQ :batch draft/extended-isupport
 * [01/24 12:18:32]  <- @label=0358 :server.com CAP reverse- ACK :batch draft/extended-isupport
 * [01/24 12:18:37]  -> server.com ISUPPORT
 * [01/24 12:18:37]  <- :server.com BATCH +1 :draft/isupport
 * [01/24 12:18:37]  <- @batch=1 :server.com 005 reverse- ACCEPT=30 AWAYLEN=200 BOT=B CALLERID=g CASEMAPPING=ascii CHANLIMIT=#:100 CHANMODES=IXZbegw,k,BEFHJLWdfjl,ACDKMNOPQRSTUcimnprstuz CHANNELLEN=60 CHANTYPES=# ELIST=CMNTU ESILENCE=CcdiNnPpTtx EXCEPTS=e :are supported by this server
 * [01/24 12:18:37]  <- @batch=1 :server.com 005 reverse- EXTBAN=,ACGNOQRSTUabcdgjmnorsuwyz EXTJWT=1 HOSTLEN=64 INVEX=I KEYLEN=30 KICKLEN=300 LINELEN=512 MAXLIST=I:100,X:100,b:100,e:100,g:100,w:100 MAXTARGETS=20 MODES=20 MONITOR=30 NAMELEN=130 :are supported by this server
 * [01/24 12:18:37]  <- @batch=1 :server.com 005 reverse- NETWORK=server.com\x20IRC NICKLEN=30 OVERRIDE=O PREFIX=(Yohv)!@%+ REMOVE reverse.im/FILEHOST=https://filehost.server.com SAFELIST SAFERATE SECURELIST=60 SILENCE=32 STATUSMSG=!@%+ TOPICLEN=330 :are supported by this server
 * [01/24 12:18:37]  <- @batch=1 :server.com 005 reverse- USERLEN=10 USERMODES=,,s,BDHILNORSTWcdghikorwxyz WATCH=32 WHOX :are supported by this server
 * [01/24 12:18:37]  <- :server.com BATCH :-1
 */

/// $ModAuthor: reverse <mike.chevronnet@gmail.com>
/// $ModDepends: core 4
/// $ModDesc: Provides the DRAFT draft/extended-isupport IRCv3 extension.

#include "inspircd.h"

#include "modules/cap.h"
#include "modules/isupport.h"
#include "modules/ircv3_batch.h"

namespace
{
	static void AppendValue(std::string& buffer, const std::string& value)
	{
		if (value.empty())
			return;

		buffer.push_back('=');
		for (const auto chr : value)
		{
			if (chr == '\0' || chr == '\n' || chr == '\r' || chr == ' ' || chr == '=' || chr == '\\')
				buffer.append(INSP_FORMAT("\\x{:02X}", chr));
			else
				buffer.push_back(chr);
		}
	}

	static void BuildNumerics(const ISupport::TokenMap& tokens, std::vector<Numeric::Numeric>& numerics)
	{
		Numeric::Numeric numeric(RPL_ISUPPORT);
		for (auto it = tokens.cbegin(); it != tokens.cend(); ++it)
		{
			numeric.push(it->first);
			std::string& token = numeric.GetParams().back();
			AppendValue(token, it->second);

			if (numeric.GetParams().size() == 12 || std::distance(it, tokens.cend()) == 1)
			{
				numeric.push("are supported by this server");
				numerics.push_back(numeric);
				numeric.GetParams().clear();
			}
		}
	}

	static ISupport::TokenMap BuildTokens(ISupport::EventProvider& isupportevprov, const std::shared_ptr<ConnectClass>& klass)
	{
		ISupport::TokenMap tokens = {
			{ "AWAYLEN",     ConvToStr(ServerInstance->Config->Limits.MaxAway)    },
			{ "CASEMAPPING", ServerInstance->Config->CaseMapping                  },
			{ "CHANNELLEN",  ConvToStr(ServerInstance->Config->Limits.MaxChannel) },
			{ "CHANTYPES",   "#"                                                  },
			{ "HOSTLEN",     ConvToStr(ServerInstance->Config->Limits.MaxHost)    },
			{ "KICKLEN",     ConvToStr(ServerInstance->Config->Limits.MaxKick)    },
			{ "LINELEN",     ConvToStr(ServerInstance->Config->Limits.MaxLine)    },
			{ "MAXTARGETS",  ConvToStr(ServerInstance->Config->MaxTargets)        },
			{ "MODES",       ConvToStr(ServerInstance->Config->Limits.MaxModes)   },
			{ "NETWORK",     ServerInstance->Config->Network                      },
			{ "NAMELEN",     ConvToStr(ServerInstance->Config->Limits.MaxReal)    },
			{ "NICKLEN",     ConvToStr(ServerInstance->Config->Limits.MaxNick)    },
			{ "TOPICLEN",    ConvToStr(ServerInstance->Config->Limits.MaxTopic)   },
			{ "USERLEN",     ConvToStr(ServerInstance->Config->Limits.MaxUser)    },
		};
		isupportevprov.Call(&ISupport::EventListener::OnBuildISupport, tokens);
		isupportevprov.Call(&ISupport::EventListener::OnBuildClassISupport, klass, tokens);
		return tokens;
	}
}

class ExtendedISupportCap final
	: public Cap::Capability
{
public:
	ExtendedISupportCap(Module* mod)
		: Cap::Capability(mod, "draft/extended-isupport")
	{
	}
};

class CommandISupport final
	: public SplitCommand
{
private:
	Cap::Capability& cap;
	ISupport::EventProvider& isupportevprov;
	IRCv3::Batch::API& batchmanager;
	IRCv3::Batch::CapReference& batchcap;

	void SendNumericList(LocalUser* user, std::vector<Numeric::Numeric>& numerics)
	{
		if (batchmanager && batchcap.IsEnabled(user))
		{
			IRCv3::Batch::Batch batch("draft/isupport");
			batchmanager->Start(batch);
			for (auto& numeric : numerics)
			{
				numeric.AddTag("batch", batchmanager.operator->(), batch.GetRefTagStr(), &batch);
				user->WriteNumeric(numeric);
			}
			batchmanager->End(batch);
			return;
		}

		for (const auto& numeric : numerics)
			user->WriteNumeric(numeric);
	}

public:
	CommandISupport(Module* mod, Cap::Capability& capref, ISupport::EventProvider& isupprov,
		IRCv3::Batch::API& batchmgr, IRCv3::Batch::CapReference& batchcapref)
		: SplitCommand(mod, "ISUPPORT")
		, cap(capref)
		, isupportevprov(isupprov)
		, batchmanager(batchmgr)
		, batchcap(batchcapref)
	{
		works_before_reg = true;
	}

	CmdResult HandleLocal(LocalUser* user, const Params& parameters) override
	{
		if (!cap.IsEnabled(user))
		{
			user->WriteNumeric(ERR_UNKNOWNCOMMAND, name, "You must request the draft/extended-isupport capability to use this command");
			return CmdResult::FAILURE;
		}

		ISupport::TokenMap tokens = BuildTokens(isupportevprov, user->GetClass());
		std::vector<Numeric::Numeric> numerics;
		BuildNumerics(tokens, numerics);
		SendNumericList(user, numerics);
		return CmdResult::SUCCESS;
	}
};

class ModuleIRCv3ExtendedISupport final
	: public Module
{
private:
	ExtendedISupportCap cap;
	IRCv3::Batch::API batchmanager;
	IRCv3::Batch::CapReference batchcap;
	ISupport::EventProvider isupportevprov;
	CommandISupport isupportcmd;

	bool rewriting = false;

public:
	ModuleIRCv3ExtendedISupport()
		: Module(VF_VENDOR, "Provides the IRCv3 draft/extended-isupport client capability.")
		, cap(this)
		, batchmanager(this)
		, batchcap(this)
		, isupportevprov(this)
		, isupportcmd(this, cap, isupportevprov, batchmanager, batchcap)
	{
	}

	ModResult OnNumeric(User* user, const Numeric::Numeric& numeric) override
	{
		if (rewriting)
			return MOD_RES_PASSTHRU;

		if (numeric.GetNumeric() != RPL_ISUPPORT)
			return MOD_RES_PASSTHRU;

		auto* localuser = IS_LOCAL(user);
		if (!localuser)
			return MOD_RES_PASSTHRU;

		if (!cap.IsEnabled(localuser))
			return MOD_RES_PASSTHRU;

		if (!batchmanager || !batchcap.IsEnabled(localuser))
			return MOD_RES_PASSTHRU;

		// Already batched.
		const auto& tags = numeric.GetParams().GetTags();
		if (tags.find("batch") != tags.end())
			return MOD_RES_PASSTHRU;

		// Rewrite this numeric into a draft/isupport batch.
		rewriting = true;
		IRCv3::Batch::Batch batch("draft/isupport");
		batchmanager->Start(batch);

		Numeric::Numeric out(RPL_ISUPPORT);
		out.GetParams() = numeric.GetParams();
		out.AddTag("batch", batchmanager.operator->(), batch.GetRefTagStr(), &batch);
		localuser->WriteNumeric(out);

		batchmanager->End(batch);
		rewriting = false;
		return MOD_RES_DENY;
	}
};

MODULE_INIT(ModuleIRCv3ExtendedISupport)
