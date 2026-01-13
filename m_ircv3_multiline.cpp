/*
 * InspIRCd -- Internet Relay Chat Daemon
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
#include "clientprotocolmsg.h"
#include "modules/cap.h"
#include "modules/ircv3_replies.h"

namespace
{
	constexpr size_t DEFAULT_MAX_BYTES = 16000;
	constexpr size_t DEFAULT_MAX_LINES = 10;

	struct MultilineLine final
	{
		std::string text;
		bool concat = false;
	};

	enum class MultilineCommand
		: uint8_t
	{
		UNKNOWN,
		PRIVMSG,
		NOTICE,
	};

	struct MultilineBatch final
	{
		std::string target;
		MultilineCommand cmd = MultilineCommand::UNKNOWN;
		std::vector<MultilineLine> lines;
	};

	struct UserBatches final
	{
		std::unordered_map<std::string, MultilineBatch> open;
	};

	class MultilineCap final
		: public Cap::Capability
	{
	private:
		std::string capvalue;

	public:
		size_t maxbytes = DEFAULT_MAX_BYTES;
		std::optional<size_t> maxlines;

		explicit MultilineCap(Module* mod)
			: Cap::Capability(mod, "draft/multiline")
		{
			// The spec requires a value; initialise a sane default until config is read.
			SetLimits(DEFAULT_MAX_BYTES, DEFAULT_MAX_LINES);
		}

		const std::string* GetValue(LocalUser* user) const override
		{
			return &capvalue;
		}

		void SetLimits(size_t bytes, const std::optional<size_t>& lines)
		{
			maxbytes = bytes;
			maxlines = lines;

			capvalue = "max-bytes=" + ConvToStr(maxbytes);
			if (maxlines)
				capvalue.append(",max-lines=").append(ConvToStr(*maxlines));

			NotifyValueChange();
		}
	};

	class MultilineTags final
		: public ClientProtocol::MessageTagProvider
	{
	private:
		Cap::Reference batchcap;
		MultilineCap& multilinecap;

	public:
		MultilineTags(Module* mod, MultilineCap& cap)
			: ClientProtocol::MessageTagProvider(mod)
			, batchcap(mod, "batch")
			, multilinecap(cap)
		{
		}

		ModResult OnProcessTag(User* user, const std::string& tagname, std::string& tagvalue) override
		{
			// We only accept the tags used by multiline batches.
			if (tagname != "batch" && tagname != "draft/multiline-concat")
				return MOD_RES_PASSTHRU;

			LocalUser* lu = IS_LOCAL(user);
			if (!lu)
				return MOD_RES_ALLOW; // Remote users are checked by their local server.

			// Require the client to have negotiated draft/multiline (and batch for @batch).
			if (!multilinecap.IsEnabled(lu))
				return MOD_RES_DENY;
			if (tagname == "batch" && !batchcap.IsEnabled(lu))
				return MOD_RES_DENY;

			if (tagname == "draft/multiline-concat" && !tagvalue.empty())
				return MOD_RES_DENY;

			return MOD_RES_ALLOW;
		}

		bool ShouldSendTag(LocalUser* user, const ClientProtocol::MessageTagData& tagdata) override
		{
			// These tags are only useful with the multiline cap.
			return multilinecap.IsEnabled(user);
		}
	};

	class MultilineMessageDetails final
		: public MessageDetails
	{
	public:
		MultilineMessageDetails(MessageType mt, const std::string& msg, const ClientProtocol::TagMap& tags)
			: MessageDetails(mt, msg, tags)
		{
		}

		bool IsCTCP(std::string_view& name, std::string_view& body) const override
		{
			if (!this->IsCTCP())
				return false;

			size_t end_of_name = text.find(' ', 2);
			size_t end_of_ctcp = text.back() == '\x1' ? 1 : 0;
			if (end_of_name == std::string::npos)
			{
				name = insp::substring_view(text, text.begin() + 1, text.end() - end_of_ctcp);
				body = std::string_view();
				return true;
			}

			name = insp::substring_view(text, text.begin() + 1, text.begin() + end_of_name);

			size_t start_of_body = text.find_first_not_of(' ', end_of_name + 1);
			if (start_of_body == std::string::npos)
			{
				body = std::string_view();
				return true;
			}

			body = insp::substring_view(text, text.begin() + start_of_body, text.end() - end_of_ctcp);
			return true;
		}

		bool IsCTCP(std::string_view& name) const override
		{
			if (!this->IsCTCP())
				return false;

			size_t end_of_name = text.find(' ', 2);
			if (end_of_name == std::string::npos)
			{
				size_t end_of_ctcp = text.back() == '\x1' ? 1 : 0;
				name = insp::substring_view(text, text.begin() + 1, text.end() - end_of_ctcp);
				return true;
			}

			name = insp::substring_view(text, text.begin() + 1, text.begin() + end_of_name);
			return true;
		}

		bool IsCTCP() const override
		{
			return (text.length() >= 2) && (text[0] == '\x1') && (text[1] != '\x1') && (text[1] != ' ');
		}
	};
}

class ModuleIRCv3Multiline final
	: public Module
{
private:
	MultilineCap cap;
	MultilineTags tags;
	Cap::Reference batchcap;
	Cap::Reference messagetagcap;
	IRCv3::Replies::CapReference stdrplcap;
	IRCv3::Replies::Fail fail;
	ClientProtocol::EventProvider batchevprov;
	SimpleExtItem<UserBatches> userbatches;
	uint64_t nextbatchid = 0;
	ChanModeReference moderatedmode;
	ChanModeReference noextmsgmode;

	struct ParsedTarget final
	{
		std::string raw;
		std::string name;
		char status = 0;
		bool ischan = false;
	};

	static ParsedTarget ParseTarget(const std::string& raw)
	{
		ParsedTarget out;
		out.raw = raw;

		const char* target = raw.c_str();
		PrefixMode* targetpfx = nullptr;
		for (PrefixMode* pfx; (pfx = ServerInstance->Modes.FindPrefix(target[0])); ++target)
		{
			// We want the lowest ranked prefix specified.
			if (!targetpfx || pfx->GetPrefixRank() < targetpfx->GetPrefixRank())
				targetpfx = pfx;
		}

		out.status = targetpfx ? targetpfx->GetPrefix() : 0;
		out.name.assign(target);
		out.ischan = !out.name.empty() && ServerInstance->Channels.IsPrefix(out.name[0]);
		return out;
	}

	static bool IsChannelTarget(const std::string& target)
	{
		return ParseTarget(target).ischan;
	}

	static ClientProtocol::TagMap CopyTagsWithoutMsgId(const ClientProtocol::TagMap& in)
	{
		ClientProtocol::TagMap out;
		for (const auto& [name, data] : in)
		{
			if (name == "msgid")
				continue;
			out.emplace(name, data);
		}
		return out;
	}

	static bool IsValidBatchId(const std::string& id)
	{
		if (id.empty() || id.size() > 64)
			return false;
		for (const char c : id)
		{
			if (!isalnum(static_cast<unsigned char>(c)))
				return false;
		}
		return true;
	}

	void SendFail(LocalUser* user, const Command* command, const std::string& code, const std::string& text)
	{
		fail.SendIfCap(user, stdrplcap, command, code, text);
	}

	template <typename... Args>
	void SendFail(LocalUser* user, const Command* command, const std::string& code, Args&&... args)
	{
		fail.SendIfCap(user, stdrplcap, command, code, std::forward<Args>(args)...);
	}

	static size_t ComputeCombinedBytes(const std::vector<MultilineLine>& lines)
	{
		size_t bytes = 0;
		for (size_t i = 0; i < lines.size(); ++i)
		{
			bytes += lines[i].text.size();
			if (i + 1 < lines.size() && !lines[i + 1].concat)
				bytes += 1; // '\n'
		}
		return bytes;
	}

	bool CanSendToChannel(LocalUser* user, Channel* chan)
	{
		if (chan->IsModeSet(noextmsgmode) && !chan->HasUser(user))
			return false;

		bool no_chan_priv = chan->GetPrefixValue(user) < VOICE_VALUE;
		if (no_chan_priv && chan->IsModeSet(moderatedmode))
			return false;

		if (no_chan_priv && ServerInstance->Config->RestrictBannedUsers != ServerConfig::BUT_NORMAL && chan->IsBanned(user))
			return false;

		return true;
	}

	void DeliverBatch(User* source, const MultilineBatch& batch)
	{
		const ParsedTarget parsed = ParseTarget(batch.target);
		if (parsed.name.empty())
			return;

		// Target can be a channel or a user.
		Channel* chan = nullptr;
		User* usertarget = nullptr;

		if (parsed.ischan)
			chan = ServerInstance->Channels.Find(parsed.name);
		else
			usertarget = ServerInstance->Users.FindNick(parsed.name, true);

		if (!chan && !usertarget)
			return;

		// Generate message tags once for the entire batch. These tags are attached to the opening
		// BATCH line for multiline recipients, and to the first fallback message line.
		ClientProtocol::TagMap batchtags;
		std::string firstnonempty;
		for (const auto& line : batch.lines)
		{
			if (!line.text.empty())
			{
				firstnonempty = line.text;
				break;
			}
		}
		if (!firstnonempty.empty())
		{
			ClientProtocol::TagMap emptytags;
			const MessageType mt = (batch.cmd == MultilineCommand::NOTICE ? MessageType::NOTICE : MessageType::PRIVMSG);
			MultilineMessageDetails details(mt, firstnonempty, emptytags);
			MessageTarget msgtarget(chan ? MessageTarget(chan, parsed.status) : MessageTarget(usertarget));
			ModResult modres;
			FIRST_MOD_RESULT(OnUserPreMessage, modres, (source, msgtarget, details));
			if (modres == MOD_RES_DENY)
				return;
			FOREACH_MOD(OnUserMessage, (source, msgtarget, details));
			batchtags = details.tags_out;
		}

		std::vector<LocalUser*> multiline_users;
		std::vector<LocalUser*> fallback_users;

		const auto IsMultilineRecipient = [this](LocalUser* lu)
		{
			return lu->IsFullyConnected() && cap.IsEnabled(lu) && batchcap.IsEnabled(lu) && messagetagcap.IsEnabled(lu);
		};

		if (chan)
		{
			for (const auto& [u, memb] : chan->GetUsers())
			{
				LocalUser* lu = IS_LOCAL(u);
				if (!lu || !lu->IsFullyConnected())
					continue;
				if (IsMultilineRecipient(lu))
					multiline_users.push_back(lu);
				else
					fallback_users.push_back(lu);
			}
		}
		else
		{
			LocalUser* lu = IS_LOCAL(usertarget);
			if (lu && lu->IsFullyConnected())
			{
				if (IsMultilineRecipient(lu))
					multiline_users.push_back(lu);
				else
					fallback_users.push_back(lu);
			}
		}

		const bool isnotice = (batch.cmd == MultilineCommand::NOTICE);
		const char* cmdstr = isnotice ? "NOTICE" : "PRIVMSG";
		const MessageType msgtype = isnotice ? MessageType::NOTICE : MessageType::PRIVMSG;
		ClientProtocol::EventProvider& rfcprov = ServerInstance->GetRFCEvents().privmsg;

		// Send to multiline-capable users.
		for (auto* lu : multiline_users)
		{
			const std::string id = ConvToStr(++nextbatchid);

			ClientProtocol::Message start("BATCH", source);
			start.PushParam("+" + id);
			start.PushParam("draft/multiline");
			start.PushParam(batch.target);
			if (!batchtags.empty())
				start.AddTags(batchtags);
			ClientProtocol::Event startevent(batchevprov, start);
			lu->Send(startevent);

			for (size_t i = 0; i < batch.lines.size(); ++i)
			{
				ClientProtocol::Message msg(cmdstr, source);
				msg.PushParam(batch.target);
				msg.PushParam(batch.lines[i].text);
				msg.AddTag("batch", &tags, id);
				if (batch.lines[i].concat)
					msg.AddTag("draft/multiline-concat", &tags, "");

				ClientProtocol::Event ev(rfcprov, msg);
				lu->Send(ev);
			}

			ClientProtocol::Message end("BATCH", ServerInstance->Config->GetServerName());
			end.PushParam("-" + id);
			ClientProtocol::Event endevent(batchevprov, end);
			lu->Send(endevent);
		}

		// Send fallback. For channels, use normal channel routing (remote servers get fallback too),
		// excluding local multiline-capable recipients to avoid duplicate delivery.
		if (chan)
		{
			CUList exemptions;
			exemptions.insert(source);
			for (auto* lu : multiline_users)
				exemptions.insert(lu);

			bool firstsent = false;
			for (const auto& line : batch.lines)
			{
				if (line.text.empty())
					continue; // MUST NOT send blank lines in fallback.

				ClientProtocol::TagMap outtags;
				if (!firstsent)
					outtags = batchtags;
				else if (!batchtags.empty())
					outtags = CopyTagsWithoutMsgId(batchtags);
				firstsent = true;

				ClientProtocol::Messages::Privmsg msg(ClientProtocol::Messages::Privmsg::nocopy, source, chan, line.text, msgtype);
				if (!outtags.empty())
					msg.AddTags(outtags);
				msg.SetSideEffect(true);
				chan->Write(ServerInstance->GetRFCEvents().privmsg, msg, 0, exemptions);
			}
		}
		else
		{
			// Local fallback delivery.
			for (auto* lu : fallback_users)
			{
				bool firstsent = false;
				for (const auto& line : batch.lines)
				{
					if (line.text.empty())
						continue; // MUST NOT send blank lines in fallback.

					ClientProtocol::TagMap outtags;
					if (!firstsent)
						outtags = batchtags;
					else if (!batchtags.empty())
						outtags = CopyTagsWithoutMsgId(batchtags);
					firstsent = true;

					ClientProtocol::Messages::Privmsg msg(ClientProtocol::Messages::Privmsg::nocopy, source, batch.target, line.text, msgtype);
					if (!outtags.empty())
						msg.AddTags(outtags);
					ClientProtocol::Event ev(ServerInstance->GetRFCEvents().privmsg, msg);
					lu->Send(ev);
				}
			}

			// Remote fallback delivery.
			if (usertarget && !IS_LOCAL(usertarget))
			{
				for (const auto& line : batch.lines)
				{
					if (line.text.empty())
						continue;

					std::vector<std::string> p{ batch.target, line.text };
					ClientProtocol::TagMap t;
					CommandBase::Params params(p, t);
					ServerInstance->Parser.CallHandler(cmdstr, params, source);
				}
			}
		}
	}

	ModResult HandleComponentLine(LocalUser* user, const std::string& command, const CommandBase::Params& parameters)
	{
		if (!cap.IsEnabled(user))
			return MOD_RES_PASSTHRU;

		const auto& tagsin = parameters.GetTags();
		auto batchit = tagsin.find("batch");
		auto concatit = tagsin.find("draft/multiline-concat");
		if (batchit == tagsin.end())
		{
			if (concatit == tagsin.end())
				return MOD_RES_PASSTHRU;

			// Concatenation without a batch is always invalid.
			SendFail(user, &cmdbatch, "MULTILINE_INVALID", "Invalid multiline batch");
			return MOD_RES_DENY;
		}

		const std::string& batchid = batchit->second.value;
		if (!IsValidBatchId(batchid))
		{
			SendFail(user, &cmdbatch, "MULTILINE_INVALID", "Invalid multiline batch");
			return MOD_RES_DENY;
		}

		UserBatches& batches = userbatches.GetRef(user);
		auto openit = batches.open.find(batchid);
		if (openit == batches.open.end())
		{
			SendFail(user, &cmdbatch, "MULTILINE_INVALID", "Invalid multiline batch");
			return MOD_RES_DENY;
		}

		// Only allow batch and draft/multiline-concat tags on component lines.
		for (const auto& [tagname, _tagdata] : tagsin)
		{
			if (tagname != "batch" && tagname != "draft/multiline-concat")
			{
				SendFail(user, &cmdbatch, "MULTILINE_INVALID", "Invalid multiline batch");
				batches.open.erase(openit);
				return MOD_RES_DENY;
			}
		}

		const bool isnotice = (command == "NOTICE");
		MultilineCommand cmd = isnotice ? MultilineCommand::NOTICE : MultilineCommand::PRIVMSG;
		if (openit->second.cmd == MultilineCommand::UNKNOWN)
			openit->second.cmd = cmd;
		else if (openit->second.cmd != cmd)
		{
			SendFail(user, &cmdbatch, "MULTILINE_INVALID", "Invalid multiline batch");
			batches.open.erase(openit);
			return MOD_RES_DENY;
		}

		if (parameters.size() < 2)
		{
			SendFail(user, &cmdbatch, "MULTILINE_INVALID", "Invalid multiline batch");
			batches.open.erase(openit);
			return MOD_RES_DENY;
		}

		const std::string& target = parameters[0];
		if (target != openit->second.target)
		{
			SendFail(user, &cmdbatch, "MULTILINE_INVALID_TARGET", openit->second.target, target, "Invalid multiline target");
			batches.open.erase(openit);
			return MOD_RES_DENY;
		}

		bool concat = (concatit != tagsin.end());
		if (concat && parameters[1].empty())
		{
			SendFail(user, &cmdbatch, "MULTILINE_INVALID", "Invalid multiline batch with concatenated blank line");
			batches.open.erase(openit);
			return MOD_RES_DENY;
		}

		openit->second.lines.push_back({ parameters[1], concat });

		// Enforce max-lines early.
		if (cap.maxlines && openit->second.lines.size() > *cap.maxlines)
		{
			SendFail(user, &cmdbatch, "MULTILINE_MAX_LINES", ConvToStr(*cap.maxlines), "Multiline batch max-lines exceeded");
			batches.open.erase(openit);
			return MOD_RES_DENY;
		}

		// Enforce max-bytes early.
		if (ComputeCombinedBytes(openit->second.lines) > cap.maxbytes)
		{
			SendFail(user, &cmdbatch, "MULTILINE_MAX_BYTES", ConvToStr(cap.maxbytes), "Multiline batch max-bytes exceeded");
			batches.open.erase(openit);
			return MOD_RES_DENY;
		}

		// Swallow the command to avoid the core rejecting blank lines or delivering early.
		return MOD_RES_DENY;
	}

	class CommandBatch final
		: public Command
	{
	private:
		ModuleIRCv3Multiline& parent;

	public:
		CommandBatch(Module* mod, ModuleIRCv3Multiline& Parent)
			: Command(mod, "BATCH", 1)
			, parent(Parent)
		{
			force_manual_route = true;
			syntax = { "(+|-|~)<id> [<type> [<target>]]" };
		}

		RouteDescriptor GetRouting(User* user, const Params& parameters) override
		{
			// Client batches are never routed across the network.
			return ROUTE_LOCALONLY;
		}

		CmdResult Handle(User* user, const Params& parameters) override
		{
			LocalUser* lu = IS_LOCAL(user);
			if (!lu)
				return CmdResult::SUCCESS;

			if (!parent.cap.IsEnabled(lu))
				return CmdResult::FAILURE;

			// Per spec, multiline depends on batch, message-tags, and standard-replies (for FAIL errors).
			if (!parent.batchcap.IsEnabled(lu) || !parent.messagetagcap.IsEnabled(lu) || !parent.stdrplcap.IsEnabled(lu))
			{
				lu->WriteNotice("*** Multiline requires CAP REQ :draft/multiline batch message-tags standard-replies");
				parent.SendFail(lu, this, "MULTILINE_INVALID", "Multiline requires the batch, message-tags, and standard-replies capabilities");
				return CmdResult::FAILURE;
			}

			const std::string& idparam = parameters[0];
			if (idparam.size() < 2)
			{
				parent.SendFail(lu, this, "MULTILINE_INVALID", "Invalid multiline batch");
				return CmdResult::FAILURE;
			}

			const char mode = idparam[0];
			const std::string id = idparam.substr(1);
			if (!IsValidBatchId(id))
			{
				parent.SendFail(lu, this, "MULTILINE_INVALID", "Invalid multiline batch");
				return CmdResult::FAILURE;
			}

			UserBatches& batches = parent.userbatches.GetRef(lu);

			if (mode == '+')
			{
				if (parameters.size() < 3 || parameters[1] != "draft/multiline")
				{
					parent.SendFail(lu, this, "MULTILINE_INVALID", "Invalid multiline batch");
					return CmdResult::FAILURE;
				}

				if (batches.open.find(id) != batches.open.end())
				{
					parent.SendFail(lu, this, "MULTILINE_INVALID", "Invalid multiline batch");
					return CmdResult::FAILURE;
				}

				MultilineBatch mb;
				mb.target = parameters[2];
				batches.open.emplace(id, std::move(mb));
				return CmdResult::SUCCESS;
			}
			else if (mode == '-')
			{
				auto it = batches.open.find(id);
				if (it == batches.open.end())
				{
					parent.SendFail(lu, this, "MULTILINE_INVALID", "Invalid multiline batch");
					return CmdResult::FAILURE;
				}

				// Per spec, multiline batches MUST contain one or more PRIVMSG/NOTICE lines.
				if (it->second.lines.empty())
				{
					parent.SendFail(lu, this, "MULTILINE_INVALID", "Invalid multiline batch");
					batches.open.erase(it);
					return CmdResult::FAILURE;
				}

				// Must not be entirely blank lines.
				bool any_nonblank = false;
				for (const auto& line : it->second.lines)
				{
					if (!line.text.empty())
					{
						any_nonblank = true;
						break;
					}
				}
				if (!any_nonblank)
				{
					parent.SendFail(lu, this, "MULTILINE_INVALID", "Invalid multiline batch with blank lines only");
					batches.open.erase(it);
					return CmdResult::FAILURE;
				}

				// Validate sendability for channel targets (we may contain blank lines which the core PRIVMSG handler would reject).
				if (IsChannelTarget(it->second.target))
				{
					Channel* chan = ServerInstance->Channels.Find(it->second.target);
					if (!chan)
					{
						parent.SendFail(lu, this, "MULTILINE_INVALID", "Invalid multiline target");
						batches.open.erase(it);
						return CmdResult::FAILURE;
					}
					if (!parent.CanSendToChannel(lu, chan))
					{
						parent.SendFail(lu, this, "MULTILINE_INVALID", "Invalid multiline batch");
						batches.open.erase(it);
						return CmdResult::FAILURE;
					}
				}

				parent.DeliverBatch(lu, it->second);
				batches.open.erase(it);
				return CmdResult::SUCCESS;
			}

			parent.SendFail(lu, this, "MULTILINE_INVALID", "Invalid multiline batch");
			return CmdResult::FAILURE;
		}
	};

	CommandBatch cmdbatch;

public:
	ModuleIRCv3Multiline()
		: Module(VF_VENDOR, "Provides the IRCv3 draft/multiline client capability.")
		, cap(this)
		, tags(this, cap)
		, batchcap(this, "batch")
		, messagetagcap(this, "message-tags")
		, stdrplcap(this)
		, fail(this)
		, batchevprov(this, "BATCH")
		, userbatches(this, "ircv3-multiline-batches", ExtensionType::USER)
		, moderatedmode(this, "moderated")
		, noextmsgmode(this, "noextmsg")
		, cmdbatch(this, *this)
	{
	}

	void ReadConfig(ConfigStatus& status) override
	{
		auto tag = ServerInstance->Config->ConfValue("multiline");
		size_t maxbytes = tag->getNum<size_t>("maxbytes", DEFAULT_MAX_BYTES);
		std::optional<size_t> maxlines;
		const auto maxlinesnum = tag->getNum<size_t>("maxlines", DEFAULT_MAX_LINES);
		if (maxlinesnum)
			maxlines = maxlinesnum;

		cap.SetLimits(maxbytes, maxlines);
	}

	ModResult OnPreCommand(std::string& command, CommandBase::Params& parameters, LocalUser* user, bool validated) override
	{
		if (!validated)
			return MOD_RES_PASSTHRU;

		if (command != "PRIVMSG" && command != "NOTICE")
			return MOD_RES_PASSTHRU;

		return HandleComponentLine(user, command, parameters);
	}
};

MODULE_INIT(ModuleIRCv3Multiline)
