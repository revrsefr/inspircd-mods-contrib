/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   Copyright (C) 2026 reverse <mike.chevronnet@gmail.com>
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

/// $ModAuthor: reverse <mike.chevronnet@gmail.com>
/// $ModDepends: core 4
/// $ModDesc: Provides the METADATA IRCv3 extension.
/// $ModConfig: <module name="m_ircv3_metadata">
/// $ModConfig: <ircv3metadata penalty="2000" maxkeys="100" maxsubs="10" maxvaluebytes="1024" maxsyncwork="10000" syncretryafter="15" beforeconnect="yes">
/// $ModConfig: <ircv3metadata operonly="yes" maxsubs="50" maxsyncwork="25000" syncretryafter="5">
/// $ModConfig: <ircv3metadatakey name="secret/*" set="no" view="oper" visibility="oper-only">
/// $ModConfig: <ircv3metadatakey name="internal/*" set="yes" view="oper" visibility="oper-only">
/// $ModConfig: <ircv3metadatakey name="public/*" set="yes" view="all" visibility="*">


#include "inspircd.h"
#include "modules/cap.h"
#include "modules/ircv3_batch.h"
#include "modules/ircv3_replies.h"
#include "modules/monitor.h"
#include <algorithm>
#include <unordered_map>
#include <unordered_set>

namespace
{
	constexpr size_t DEFAULT_MAX_KEYS = 100;
	constexpr size_t DEFAULT_MAX_SUBS = 100;
	constexpr size_t DEFAULT_MAX_VALUE_BYTES = 4096;

	bool IsValidMetadataKey(const std::string& key)
	{
		if (key.empty())
			return false;

		for (const char chr : key)
		{
			if ((chr >= 'a' && chr <= 'z')
				|| (chr >= '0' && chr <= '9')
				|| chr == '_' || chr == '.' || chr == '/' || chr == '-' )
			{
				continue;
			}
			return false;
		}
		return true;
	}

	std::string NormalizeTarget(LocalUser* user, const std::string& raw)
	{
		if (raw == "*")
		{
			// During registration the client does not yet have a nick.
			if (user->connected & User::CONN_NICK)
				return user->nick;
			return "*";
		}
		return raw;
	}

	bool IsValidUtf8(const std::string& value)
	{
		// Minimal UTF-8 validation. Rejects overlong encodings, surrogate halves, and codepoints > U+10FFFF.
		const unsigned char* ptr = reinterpret_cast<const unsigned char*>(value.data());
		const unsigned char* end = ptr + value.size();
		while (ptr < end)
		{
			const unsigned char c0 = *ptr++;
			if (c0 <= 0x7F)
				continue;

			unsigned int need = 0;
			uint32_t cp = 0;
			uint32_t mincp = 0;
			if ((c0 & 0xE0) == 0xC0)
			{
				need = 1;
				cp = c0 & 0x1F;
				mincp = 0x80;
			}
			else if ((c0 & 0xF0) == 0xE0)
			{
				need = 2;
				cp = c0 & 0x0F;
				mincp = 0x800;
			}
			else if ((c0 & 0xF8) == 0xF0)
			{
				need = 3;
				cp = c0 & 0x07;
				mincp = 0x10000;
			}
			else
			{
				return false;
			}

			if (static_cast<size_t>(end - ptr) < need)
				return false;

			for (unsigned int i = 0; i < need; ++i)
			{
				const unsigned char cx = *ptr++;
				if ((cx & 0xC0) != 0x80)
					return false;
				cp = (cp << 6) | (cx & 0x3F);
			}

			if (cp < mincp)
				return false;
			if (cp > 0x10FFFF)
				return false;
			if (cp >= 0xD800 && cp <= 0xDFFF)
				return false;
			if (cp == 0xFFFE || cp == 0xFFFF)
				return false;
		}
		return true;
	}
}

class ModuleIRCv3Metadata;

struct MetadataStore final
{
	// Key -> Value.
	std::unordered_map<std::string, std::string> values;
};

struct MetadataSubs final
{
	// Subscribed keys.
	std::unordered_set<std::string> keys;
};

class MetadataExt final
	: public ExtensionItem
{
public:
	MetadataExt(Module* mod, const std::string& extname, ExtensionType exttype)
		: ExtensionItem(mod, extname, exttype)
	{
	}

	MetadataStore* Get(const Extensible* container) const
	{
		return static_cast<MetadataStore*>(GetRaw(container));
	}

	MetadataStore& GetOrCreate(Extensible* container)
	{
		auto* store = Get(container);
		if (!store)
		{
			store = new MetadataStore();
			SetRaw(container, store);
		}
		return *store;
	}

	void Unset(Extensible* container)
	{
		Delete(container, UnsetRaw(container));
	}

	void Delete(Extensible* container, void* item) override
	{
		delete static_cast<MetadataStore*>(item);
	}

	std::string ToInternal(const Extensible* container, void* item) const noexcept override
	{
		const auto* store = static_cast<const MetadataStore*>(item);
		std::string out;
		for (const auto& [key, value] : store->values)
		{
			// Format: key\nvalue\n (with escaping) -- avoids spaces and allows empty values.
			// NOTE: This is an internal serialization format and is not user-visible.
			out.append(key);
			out.push_back('\n');
			for (const char chr : value)
			{
				if (chr == '\\' || chr == '\n')
					out.push_back('\\');
				out.push_back(chr);
			}
			out.push_back('\n');
		}
		return out;
	}

	void FromInternal(Extensible* container, const std::string& value) noexcept override
	{
		// Best-effort parsing of the internal format produced by ToInternal().
		MetadataStore parsed;
		size_t pos = 0;
		while (pos < value.size())
		{
			size_t keyend = value.find('\n', pos);
			if (keyend == std::string::npos)
				break;
			std::string key = value.substr(pos, keyend - pos);
			pos = keyend + 1;

			size_t valend = value.find('\n', pos);
			if (valend == std::string::npos)
				break;
			std::string raw = value.substr(pos, valend - pos);
			pos = valend + 1;

			std::string val;
			val.reserve(raw.size());
			bool esc = false;
			for (const char chr : raw)
			{
				if (!esc && chr == '\\')
				{
					esc = true;
					continue;
				}
				esc = false;
				val.push_back(chr);
			}

			if (!key.empty())
				parsed.values.emplace(std::move(key), std::move(val));
		}

		// Replace existing store.
		Unset(container);
		if (!parsed.values.empty())
			SetRaw(container, new MetadataStore(std::move(parsed)));
	}
};

class SubsExt final
	: public SimpleExtItem<MetadataSubs>
{
public:
	SubsExt(Module* mod)
		: SimpleExtItem<MetadataSubs>(mod, "metadata-subs", ExtensionType::USER)
	{
	}

	std::string ToInternal(const Extensible* container, void* item) const noexcept override
	{
		const auto* subs = static_cast<const MetadataSubs*>(item);
		std::string out;
		for (const auto& key : subs->keys)
		{
			if (!out.empty())
				out.push_back(' ');
			out.append(key);
		}
		return out;
	}

	void FromInternal(Extensible* container, const std::string& value) noexcept override
	{
		MetadataSubs parsed;
		irc::spacesepstream ss(value);
		std::string key;
		while (ss.GetToken(key))
		{
			if (IsValidMetadataKey(key))
				parsed.keys.emplace(key);
		}
		Unset(container, false);
		if (!parsed.keys.empty())
			Set(container, parsed, false);
	}
};

struct MetadataRate final
{
	time_t windowstart = 0;
	unsigned int count = 0;
};

class RateExt final
	: public SimpleExtItem<MetadataRate>
{
public:
	RateExt(Module* mod)
		: SimpleExtItem<MetadataRate>(mod, "metadata-rate", ExtensionType::USER)
	{
	}
};

class MetadataCap final
	: public Cap::Capability
{

public:
	struct Limits final
	{
		size_t maxkeys = DEFAULT_MAX_KEYS;
		size_t maxsubs = DEFAULT_MAX_SUBS;
		size_t maxvaluebytes = DEFAULT_MAX_VALUE_BYTES;
		bool beforeconnect = true;
		size_t maxsyncmembers = 0;
		size_t maxsyncwork = 0;
		unsigned int syncretryafter = 4;
	};

	struct Override final
	{
		std::string klass;
		bool operonly = false;
		Limits limits;
	};

private:

	Limits defaults;
	std::vector<Override> overrides;

	mutable std::string capvalue;

public:
	const Limits& GetLimits(LocalUser* user) const
	{
		// Default to global limits.
		const Limits* out = &defaults;
		if (!user)
			return *out;

		// Apply the *last* matching override (config order gives predictable behaviour).
		const std::string& userklass = user->GetClass()->GetName();
		for (const auto& ov : overrides)
		{
			if (ov.operonly && !user->IsOper())
				continue;
			if (!ov.klass.empty() && !insp::equalsci(ov.klass, userklass))
				continue;
			out = &ov.limits;
		}
		return *out;
	}

	MetadataCap(Module* mod)
		: Cap::Capability(mod, "draft/metadata-2")
	{
	}

	const std::string* GetValue(LocalUser* user) const override
	{
		const auto& lim = GetLimits(user);
		capvalue.clear();
		if (lim.beforeconnect)
			capvalue.append("before-connect,");
		capvalue.append("max-subs=").append(ConvToStr(lim.maxsubs));
		capvalue.append(",max-keys=").append(ConvToStr(lim.maxkeys));
		capvalue.append(",max-value-bytes=").append(ConvToStr(lim.maxvaluebytes));
		return &capvalue;
	}

	void SetConfig(const Limits& newdefaults, std::vector<Override>&& newoverrides)
	{
		defaults = newdefaults;
		overrides = std::move(newoverrides);
		NotifyValueChange();
	}
};

class CommandMetadata final
	: public Command
{
private:
	ModuleIRCv3Metadata& parent;

public:
	CommandMetadata(Module* mod, ModuleIRCv3Metadata& parentref);
	RouteDescriptor GetRouting(User* user, const Params& parameters) override;
	CmdResult Handle(User* user, const Params& parameters) override;
};

class ModuleIRCv3Metadata final
	: public Module
{
private:
	friend class CommandMetadata;

	struct KeyRule final
	{
		enum class View
		{
			ALL,
			SELF,
			OPER,
		};

		std::string name;
		bool settable = true;
		View view = View::ALL;
		std::string visibility = "*";
	};

	MetadataCap cap;
	Cap::Reference batchcap;
	IRCv3::Batch::API batchmanager;
	IRCv3::Replies::Fail failrpl;
	IRCv3::Replies::CapReference stdrplcap;
	Monitor::API monitorapi;
	ClientProtocol::EventProvider metadatamsgevprov;

	RateExt rateext;
	unsigned int ratelimit = 0;
	unsigned int rateperiod = 60;
	std::vector<KeyRule> keyrules;

	CommandMetadata cmd;
	MetadataExt usermeta;
	MetadataExt chanmeta;
	SubsExt subs;

	static bool CanWriteUserMetadata(User* source, User* target)
	{
		if (source == target)
			return true;
		return source->HasPrivPermission("users/metadata");
	}

	static bool CanWriteChanMetadata(User* source, Channel* chan)
	{
		if (!chan->HasUser(source))
			return false;
		return chan->GetPrefixValue(source) >= OP_VALUE;
	}

	const KeyRule* GetKeyRule(const std::string& key) const
	{
		const KeyRule* out = nullptr;
		for (const auto& rule : keyrules)
		{
			if (rule.name.empty())
				continue;
			if (!InspIRCd::Match(key, rule.name))
				continue;
			out = &rule;
		}
		return out;
	}

	bool CanReadMetadata(User* source, const std::string& key, const std::string& targetname) const
	{
		const KeyRule* rule = GetKeyRule(key);
		if (!rule)
			return true;

		switch (rule->view)
		{
			case KeyRule::View::ALL:
				return true;
			case KeyRule::View::SELF:
				return (source && insp::equalsci(source->nick, targetname));
			case KeyRule::View::OPER:
				return (source && source->IsOper());
		}
		return true;
	}

	bool CanSetMetadata(User* source, const std::string& key, const std::string& targetname) const
	{
		const KeyRule* rule = GetKeyRule(key);
		if (rule && !rule->settable)
			return false;

		// Do not allow setting keys a user can't read back (avoids leaking restricted keys via SET/CLEAR replies).
		if (!CanReadMetadata(source, key, targetname))
			return false;

		return true;
	}

	std::string GetVisibility(User* source, const std::string& key, const std::string& targetname) const
	{
		const KeyRule* rule = GetKeyRule(key);
		if (!rule)
			return "*";
		if (!CanReadMetadata(source, key, targetname))
			return "*";
		return rule->visibility.empty() ? "*" : rule->visibility;
	}

	std::string GetVisibilityForAll(const std::string& key) const
	{
		const KeyRule* rule = GetKeyRule(key);
		if (!rule)
			return "*";
		if (rule->view != KeyRule::View::ALL)
			return "*";
		return rule->visibility.empty() ? "*" : rule->visibility;
	}

	bool IsPublicKey(const std::string& key) const
	{
		const KeyRule* rule = GetKeyRule(key);
		return (!rule || rule->view == KeyRule::View::ALL);
	}

	bool CheckRateLimit(LocalUser* user, const Command* command, const std::string& target, const std::string& key)
	{
		if (!ratelimit || !rateperiod)
			return true;

		auto& state = rateext.GetRef(user);
		const time_t now = ServerInstance->Time();
		if (!state.windowstart || (now - state.windowstart) >= static_cast<time_t>(rateperiod))
		{
			state.windowstart = now;
			state.count = 0;
		}

		if (state.count >= ratelimit)
		{
			unsigned int retryafter = 1;
			const time_t elapsed = now - state.windowstart;
			if (elapsed >= 0 && elapsed < static_cast<time_t>(rateperiod))
				retryafter = static_cast<unsigned int>(rateperiod - elapsed);
			SendFail(user, command, "RATE_LIMITED", target, key, ConvToStr(retryafter), "too many changes");
			return false;
		}

		++state.count;
		return true;
	}

	void SendSyncLater(LocalUser* user, const std::string& target, unsigned int retryafter)
	{
		Numeric::Numeric n(RPL_METADATASYNCLATER);
		n.push(target);
		if (retryafter)
			n.push(ConvToStr(retryafter));
		user->WriteNumeric(n);
	}

	bool ShouldPostponeSync(LocalUser* user, Channel* chan) const
	{
		const auto& lim = cap.GetLimits(user);

		// Only postpone when configured and when the client has something subscribed.
		const MetadataSubs* s = subs.Get(user);
		if (!s || s->keys.empty())
			return false;

		const size_t members = chan->GetUsers().size();
		if (lim.maxsyncwork)
		{
			// Rough but cheap estimate of work. Our sync paths are essentially:
			// - check each member (O(members))
			// - for each member, potentially emit up to subscribed_keys METADATA messages
			// We use (members + 1) to account for the channel entity itself.
			const size_t work = (members + 1) * s->keys.size();
			return work > lim.maxsyncwork;
		}

		// Backwards-compatible fallback: pure member threshold.
		if (lim.maxsyncmembers)
			return members > lim.maxsyncmembers;

		return false;
	}

	void SendNoSuchTarget(LocalUser* user, const std::string& target)
	{
		Numeric::Numeric n(!target.empty() && target[0] == '#' ? ERR_NOSUCHCHANNEL : ERR_NOSUCHNICK);
		n.push(target);
		n.push(!target.empty() && target[0] == '#' ? "No such channel" : "No such nick/channel");
		user->WriteNumeric(n);
	}

	void SendNotOnChannel(LocalUser* user, const std::string& chan)
	{
		Numeric::Numeric n(ERR_NOTONCHANNEL);
		n.push(chan);
		n.push("You're not on that channel");
		user->WriteNumeric(n);
	}

	void SendChanOpPrivsNeeded(LocalUser* user, const std::string& chan)
	{
		Numeric::Numeric n(ERR_CHANOPRIVSNEEDED);
		n.push(chan);
		n.push("You're not channel operator");
		user->WriteNumeric(n);
	}

	void SendNoPrivileges(LocalUser* user)
	{
		Numeric::Numeric n(ERR_NOPRIVILEGES);
		n.push("Permission Denied- You're not an IRC operator");
		user->WriteNumeric(n);
	}

	void SendFail(LocalUser* user, const Command* command, const std::string& code, const std::string& p1, const std::string& p2, const std::string& desc)
	{
		failrpl.SendIfCap(user, stdrplcap, command, code, p1, p2, desc);
	}

	void SendFail(LocalUser* user, const Command* command, const std::string& code, const std::string& p1, const std::string& p2, const std::string& p3, const std::string& desc)
	{
		failrpl.SendIfCap(user, stdrplcap, command, code, p1, p2, p3, desc);
	}

	void SendFail(LocalUser* user, const Command* command, const std::string& code, const std::string& p1, const std::string& desc)
	{
		failrpl.SendIfCap(user, stdrplcap, command, code, p1, desc);
	}

	void SendFail(LocalUser* user, const Command* command, const std::string& code, const std::string& desc)
	{
		failrpl.SendIfCap(user, stdrplcap, command, code, desc);
	}

	void SendKeyValue(LocalUser* user, const std::string& target, const std::string& key, const std::string& visibility, const std::string& value, IRCv3::Batch::Batch* batch)
	{
		Numeric::Numeric n(RPL_KEYVALUE);
		n.push(target);
		n.push(key);
		n.push(visibility);
		n.push(value);
		if (batch && batch->IsRunning() && batchmanager)
			n.AddTag("batch", batchmanager.operator->(), batch->GetRefTagStr(), batch);
		user->WriteNumeric(n);
	}

	void SendKeyNotSet(LocalUser* user, const std::string& target, const std::string& key, IRCv3::Batch::Batch* batch)
	{
		Numeric::Numeric n(RPL_KEYNOTSET);
		n.push(target);
		n.push(key);
		n.push("key not set");
		if (batch && batch->IsRunning() && batchmanager)
			n.AddTag("batch", batchmanager.operator->(), batch->GetRefTagStr(), batch);
		user->WriteNumeric(n);
	}

	void SendMetadataMsg(LocalUser* user, const std::string& target, const std::string& key, const std::string& visibility, const std::string& value, IRCv3::Batch::Batch* batch = nullptr)
	{
		ClientProtocol::Message msg("METADATA", ServerInstance->Config->GetServerName());
		msg.PushParam(target);
		msg.PushParam(key);
		msg.PushParam(visibility);
		msg.PushParam(value);
		if (batch)
			batch->AddToBatch(msg);
		user->Send(metadatamsgevprov, msg);
	}

	void SendMetadataBatchStart(LocalUser* user, IRCv3::Batch::Batch& batch, const std::string& targetname)
	{
		if (!batchmanager || !batchcap.IsEnabled(user))
			return;
		batchmanager->Start(batch);
		batch.GetBatchStartMessage().PushParamRef(targetname);
	}

	void SendMetadataBatchEnd(IRCv3::Batch::Batch& batch)
	{
		if (batchmanager)
			batchmanager->End(batch);
	}

	void SyncToUser(LocalUser* user, const std::string& targetname, const MetadataStore* store, const MetadataSubs* subfilter, IRCv3::Batch::Batch* batch)
	{
		if (!store)
			return;
		for (const auto& [key, value] : store->values)
		{
			if (subfilter && subfilter->keys.find(key) == subfilter->keys.end())
				continue;
			if (!CanReadMetadata(user, key, targetname))
				continue;
			SendMetadataMsg(user, targetname, key, GetVisibility(user, key, targetname), value, batch);
		}
	}

	void NotifyUserMetadataChange(User* target, const std::string& key, const std::string& value)
	{
		// Notify local neighbors and monitor watchers. This is a minimal implementation.
		// We only notify for keys a client subscribed to.
		uint64_t sentid = ServerInstance->Users.NextAlreadySentId();

		struct NotifyNeighbor final
			: public User::ForEachNeighborHandler
		{
			ModuleIRCv3Metadata& parent;
			User* target;
			const std::string& key;
			const std::string& value;
			uint64_t sentid;

			NotifyNeighbor(ModuleIRCv3Metadata& p, User* t, const std::string& k, const std::string& v, uint64_t id)
				: parent(p)
				, target(t)
				, key(k)
				, value(v)
				, sentid(id)
			{
			}

			void Execute(LocalUser* user) override
			{
				if (user->already_sent == sentid)
					return;
				user->already_sent = sentid;
				if (!parent.cap.IsEnabled(user))
					return;
				MetadataSubs* s = parent.subs.Get(user);
				if (!s || s->keys.find(key) == s->keys.end())
					return;
				if (user == target)
					return; // Exclude self changes.
				if (!parent.CanReadMetadata(user, key, target->nick))
					return;
				parent.SendMetadataMsg(user, target->nick, key, parent.GetVisibility(user, key, target->nick), value);
			}
		};

		NotifyNeighbor nh(*this, target, key, value, sentid);
		if (IS_LOCAL(target))
			static_cast<LocalUser*>(target)->ForEachNeighbor(nh, true);
		else
			target->ForEachNeighbor(nh, false);

		// Notify monitor watchers with cap. We can not filter per watcher, so only broadcast public keys.
		if (IsPublicKey(key))
		{
			ClientProtocol::Message msg("METADATA", ServerInstance->Config->GetServerName());
			msg.PushParam(target->nick);
			msg.PushParam(key);
			msg.PushParam(GetVisibilityForAll(key));
			msg.PushParam(value);
			ClientProtocol::Event protoev(metadatamsgevprov, msg);
			Monitor::WriteWatchersWithCap(monitorapi, target, protoev, cap, sentid);
		}
	}

	void NotifyChanMetadataChange(Channel* chan, const std::string& key, const std::string& value)
	{
		for (const auto& [user, memb] : chan->GetUsers())
		{
			LocalUser* lu = IS_LOCAL(user);
			if (!lu)
				continue;
			if (!cap.IsEnabled(lu))
				continue;
			MetadataSubs* s = subs.Get(lu);
			if (!s || s->keys.find(key) == s->keys.end())
				continue;
			if (!CanReadMetadata(lu, key, chan->name))
				continue;
			SendMetadataMsg(lu, chan->name, key, GetVisibility(lu, key, chan->name), value);
		}
	}

public:
	ModuleIRCv3Metadata()
		: Module(VF_VENDOR | VF_OPTCOMMON, "Provides support for the IRCv3 draft/metadata-2 capability.")
		, cap(this)
		, batchcap(this, "batch")
		, batchmanager(this)
		, failrpl(this)
		, stdrplcap(this)
		, monitorapi(this)
		, metadatamsgevprov(this, "METADATA")
		, rateext(this)
		, cmd(this, *this)
		, usermeta(this, "metadata-user", ExtensionType::USER)
		, chanmeta(this, "metadata-chan", ExtensionType::CHANNEL)
		, subs(this)
	{
	}

	void ReadConfig(ConfigStatus& status) override
	{
		(void)status;
		auto tags = ServerInstance->Config->ConfTags("ircv3metadata");
		auto keytags = ServerInstance->Config->ConfTags("ircv3metadatakey");

		unsigned int newpenalty = 1000;
		unsigned int newratelimit = 0;
		unsigned int newrateperiod = 60;

		MetadataCap::Limits defaults;
		std::vector<MetadataCap::Override> overrides;

		// Use the first tag as the base defaults (matches existing behaviour).
		auto firsttag = tags.begin();
		if (firsttag != tags.end())
		{
			const auto& tag = firsttag->second;
			newpenalty = tag->getNum<unsigned int>("penalty", newpenalty);
			newratelimit = tag->getNum<unsigned int>("ratelimit", newratelimit);
			newrateperiod = tag->getNum<unsigned int>("rateperiod", newrateperiod);
			defaults.maxkeys = tag->getNum<size_t>("maxkeys", DEFAULT_MAX_KEYS);
			defaults.maxsubs = tag->getNum<size_t>("maxsubs", DEFAULT_MAX_SUBS);
			defaults.maxvaluebytes = tag->getNum<size_t>("maxvaluebytes", DEFAULT_MAX_VALUE_BYTES);
			defaults.maxsyncmembers = tag->getNum<size_t>("maxsyncmembers", 0);
			defaults.maxsyncwork = tag->getNum<size_t>("maxsyncwork", 0);
			defaults.syncretryafter = tag->getNum<unsigned int>("syncretryafter", 4);
			defaults.beforeconnect = tag->getBool("beforeconnect", true);
		}

		// Parse per-class / oper-only overrides.
		for (const auto& [_, tag] : tags)
		{
			const std::string klass = tag->getString("class");
			const bool operonly = tag->getBool("operonly", false);
			if (klass.empty() && !operonly)
				continue; // This is a plain default tag.

			MetadataCap::Override ov;
			ov.klass = klass;
			ov.operonly = operonly;
			ov.limits = defaults;

			ov.limits.maxkeys = tag->getNum<size_t>("maxkeys", ov.limits.maxkeys);
			ov.limits.maxsubs = tag->getNum<size_t>("maxsubs", ov.limits.maxsubs);
			ov.limits.maxvaluebytes = tag->getNum<size_t>("maxvaluebytes", ov.limits.maxvaluebytes);
			ov.limits.maxsyncmembers = tag->getNum<size_t>("maxsyncmembers", ov.limits.maxsyncmembers);
			ov.limits.maxsyncwork = tag->getNum<size_t>("maxsyncwork", ov.limits.maxsyncwork);
			ov.limits.syncretryafter = tag->getNum<unsigned int>("syncretryafter", ov.limits.syncretryafter);
			ov.limits.beforeconnect = tag->getBool("beforeconnect", ov.limits.beforeconnect);

			overrides.push_back(std::move(ov));
		}

		cap.SetConfig(defaults, std::move(overrides));
		cmd.penalty = std::min(newpenalty, 60000u);
		ratelimit = newratelimit;
		rateperiod = std::min(newrateperiod, 86400u);

		std::vector<KeyRule> newkeyrules;
		for (const auto& [_, tag] : keytags)
		{
			KeyRule rule;
			rule.name = tag->getString("name");
			if (rule.name.empty())
				continue;
			rule.settable = tag->getBool("set", true);
			rule.visibility = tag->getString("visibility", "*");
			const std::string view = tag->getString("view", "all");
			if (insp::equalsci(view, "all"))
				rule.view = KeyRule::View::ALL;
			else if (insp::equalsci(view, "self"))
				rule.view = KeyRule::View::SELF;
			else if (insp::equalsci(view, "oper") || insp::equalsci(view, "opers"))
				rule.view = KeyRule::View::OPER;
			else
				rule.view = KeyRule::View::ALL;
			newkeyrules.push_back(std::move(rule));
		}
		keyrules = std::move(newkeyrules);
	}

	void OnUserConnect(LocalUser* user) override
	{
		// If the user negotiated draft/metadata-2 during registration and the server
		// advertised before-connect then send their current metadata in a metadata batch.
		if (!cap.IsEnabled(user) || !batchcap.IsEnabled(user) || !stdrplcap.IsEnabled(user))
			return;

		const MetadataStore* store = usermeta.Get(user);
		if (batchmanager)
		{
			// Per spec, MUST send an empty batch if none exists.
			IRCv3::Batch::Batch batch("metadata");
			SendMetadataBatchStart(user, batch, user->nick);
			SyncToUser(user, user->nick, store, nullptr, &batch);
			SendMetadataBatchEnd(batch);
			return;
		}

		// No batch capability; send unbatched METADATA messages (or nothing if empty).
		SyncToUser(user, user->nick, store, nullptr, nullptr);
	}

	void OnPostJoin(Membership* memb) override
	{
		LocalUser* user = IS_LOCAL(memb->user);
		if (!user)
			return;
		if (!cap.IsEnabled(user) || !batchcap.IsEnabled(user) || !stdrplcap.IsEnabled(user))
			return;

		MetadataSubs* s = subs.Get(user);
		if (!s || s->keys.empty())
			return;

		// Postpone sync on large channels to avoid stalling the IO loop.
		if (ShouldPostponeSync(user, memb->chan))
		{
			SendSyncLater(user, memb->chan->name, cap.GetLimits(user).syncretryafter);
			return;
		}

		// Send subscribed metadata for the channel and its members in a metadata batch.
		IRCv3::Batch::Batch batch("metadata");
		IRCv3::Batch::Batch* batchptr = nullptr;
		if (batchmanager)
		{
			SendMetadataBatchStart(user, batch, memb->chan->name);
			batchptr = &batch;
		}

		// Channel metadata.
		SyncToUser(user, memb->chan->name, chanmeta.Get(memb->chan), s, batchptr);

		// User metadata for all members.
		for (const auto& [memberuser, member] : memb->chan->GetUsers())
			SyncToUser(user, memberuser->nick, usermeta.Get(memberuser), s, batchptr);

		if (batchptr)
			SendMetadataBatchEnd(batch);
	}
};

CommandMetadata::CommandMetadata(Module* mod, ModuleIRCv3Metadata& parentref)
	: Command(mod, "METADATA", 2, 0)
	, parent(parentref)
{
	force_manual_route = true;
	works_before_reg = true;
	syntax = { "<Target> LIST", "<Target> GET <key1> [<key2> ...]", "<Target> SET <Key> [:Value]", "<Target> CLEAR", "<Target> SYNC", "* SUB <key1> [<key2> ...]", "* UNSUB <key1> [<key2> ...]", "* SUBS" };
}

RouteDescriptor CommandMetadata::GetRouting(User* user, const Params& parameters)
{
	// METADATA is client-side only and does not route across the network.
	return ROUTE_LOCALONLY;
}

CmdResult CommandMetadata::Handle(User* user, const Params& parameters)
{
	LocalUser* lu = IS_LOCAL(user);
	if (!lu)
		return CmdResult::SUCCESS;

	// Require modern IRCv3 behaviour. This module is designed around batched replies and
	// standard replies; without them client behaviour is inconsistent.
	if (!parent.cap.IsEnabled(lu) || !parent.batchcap.IsEnabled(lu) || !parent.stdrplcap.IsEnabled(lu))
	{
		lu->WriteNotice("*** METADATA requires CAP REQ :draft/metadata-2 batch standard-replies");
		parent.SendFail(lu, this, "NEED_CAPS", "draft/metadata-2 batch standard-replies", "missing required capabilities");
		return CmdResult::FAILURE;
	}

	const std::string target = NormalizeTarget(lu, parameters[0]);
	const std::string subcmd = parameters[1];

	if (irc::equals(subcmd, "LIST"))
	{
		Extensible* ext = nullptr;
		std::string targetname = target;
		MetadataExt* metaext = nullptr;

		if (!target.empty() && target[0] == '#')
		{
			Channel* chan = ServerInstance->Channels.Find(target);
			if (!chan)
			{
				parent.SendFail(lu, this, "INVALID_TARGET", target, "invalid metadata target");
				return CmdResult::FAILURE;
			}
			ext = chan;
			metaext = &parent.chanmeta;
		}
		else
		{
			User* tgtuser = (target == "*") ? user : ServerInstance->Users.FindNick(target, true);
			if (!tgtuser)
			{
				parent.SendFail(lu, this, "INVALID_TARGET", target, "invalid metadata target");
				return CmdResult::FAILURE;
			}
			ext = tgtuser;
			metaext = &parent.usermeta;
			targetname = tgtuser->nick;
		}

		IRCv3::Batch::Batch batch("metadata");
		IRCv3::Batch::Batch* batchptr = nullptr;
		if (parent.batchmanager && parent.batchcap.IsEnabled(lu))
		{
			parent.batchmanager->Start(batch);
			batch.GetBatchStartMessage().PushParamRef(targetname);
			batchptr = &batch;
		}

		const MetadataStore* store = metaext->Get(ext);
		if (store)
		{
			for (const auto& [key, value] : store->values)
			{
				if (!parent.CanReadMetadata(user, key, targetname))
					continue;
				parent.SendKeyValue(lu, targetname, key, parent.GetVisibility(user, key, targetname), value, batchptr);
			}
		}

		if (batchptr)
			parent.batchmanager->End(batch);
		return CmdResult::SUCCESS;
	}
	else if (irc::equals(subcmd, "GET"))
	{
		if (parameters.size() < 3)
			return CmdResult::INVALID;

		Extensible* ext = nullptr;
		std::string targetname = target;
		MetadataExt* metaext = nullptr;
		if (!target.empty() && target[0] == '#')
		{
			Channel* chan = ServerInstance->Channels.Find(target);
			if (!chan)
			{
				parent.SendFail(lu, this, "INVALID_TARGET", target, "invalid metadata target");
				return CmdResult::FAILURE;
			}
			ext = chan;
			metaext = &parent.chanmeta;
		}
		else
		{
			User* tgtuser = (target == "*") ? user : ServerInstance->Users.FindNick(target, true);
			if (!tgtuser)
			{
				parent.SendFail(lu, this, "INVALID_TARGET", target, "invalid metadata target");
				return CmdResult::FAILURE;
			}
			ext = tgtuser;
			metaext = &parent.usermeta;
			targetname = tgtuser->nick;
		}

		IRCv3::Batch::Batch batch("metadata");
		IRCv3::Batch::Batch* batchptr = nullptr;
		if (parent.batchmanager && parent.batchcap.IsEnabled(lu))
		{
			parent.batchmanager->Start(batch);
			batch.GetBatchStartMessage().PushParamRef(targetname);
			batchptr = &batch;
		}

		const MetadataStore* store = metaext->Get(ext);
		for (size_t idx = 2; idx < parameters.size(); ++idx)
		{
			const std::string& key = parameters[idx];
			if (!IsValidMetadataKey(key))
			{
				parent.SendFail(lu, this, "KEY_INVALID", key, "invalid key");
				continue;
			}
			if (!parent.CanReadMetadata(user, key, targetname))
			{
				parent.SendFail(lu, this, "KEY_NO_PERMISSION", targetname, key, "permission denied");
				continue;
			}
			if (!store)
				parent.SendKeyNotSet(lu, targetname, key, batchptr);
			else
			{
				auto it = store->values.find(key);
				if (it == store->values.end())
					parent.SendKeyNotSet(lu, targetname, key, batchptr);
				else
					parent.SendKeyValue(lu, targetname, key, parent.GetVisibility(user, key, targetname), it->second, batchptr);
			}
		}

		if (batchptr)
			parent.batchmanager->End(batch);
		return CmdResult::SUCCESS;
	}
	else if (irc::equals(subcmd, "SET"))
	{
		if (parameters.size() < 3)
			return CmdResult::INVALID;

		const auto& limits = parent.cap.GetLimits(lu);

		const std::string& key = parameters[2];
		if (!IsValidMetadataKey(key))
		{
			parent.SendFail(lu, this, "KEY_INVALID", key, "invalid key");
			return CmdResult::FAILURE;
		}

		const bool hasvalue = (parameters.size() >= 4);
		const std::string value = hasvalue ? parameters[3] : std::string();

		if (hasvalue && value.size() > limits.maxvaluebytes)
		{
			parent.SendFail(lu, this, "VALUE_INVALID", "value is too long");
			return CmdResult::FAILURE;
		}

		if (hasvalue && !IsValidUtf8(value))
		{
			parent.SendFail(lu, this, "VALUE_INVALID", "value is not valid UTF-8");
			return CmdResult::FAILURE;
		}

		if (!target.empty() && target[0] == '#')
		{
			Channel* chan = ServerInstance->Channels.Find(target);
			if (!chan)
			{
				parent.SendFail(lu, this, "INVALID_TARGET", target, "invalid metadata target");
				return CmdResult::FAILURE;
			}
			if (!parent.CanWriteChanMetadata(user, chan))
			{
				parent.SendFail(lu, this, "KEY_NO_PERMISSION", chan->name, key, "permission denied");
				return CmdResult::FAILURE;
			}
			if (!parent.CanSetMetadata(user, key, chan->name))
			{
				parent.SendFail(lu, this, "KEY_NO_PERMISSION", chan->name, key, "permission denied");
				return CmdResult::FAILURE;
			}
			if (!parent.CheckRateLimit(lu, this, chan->name, key))
				return CmdResult::FAILURE;

			if (!hasvalue)
			{
				// Remove the key.
				MetadataStore* store = parent.chanmeta.Get(chan);
				if (!store)
				{
					parent.SendFail(lu, this, "KEY_NOT_SET", chan->name, key, "key not set");
					return CmdResult::FAILURE;
				}
				auto it = store->values.find(key);
				if (it == store->values.end())
				{
					parent.SendFail(lu, this, "KEY_NOT_SET", chan->name, key, "key not set");
					return CmdResult::FAILURE;
				}
				store->values.erase(it);
				if (store->values.empty())
					parent.chanmeta.Unset(chan);
				parent.SendKeyNotSet(lu, chan->name, key, nullptr);
				parent.NotifyChanMetadataChange(chan, key, std::string());
				return CmdResult::SUCCESS;
			}

			MetadataStore& store = parent.chanmeta.GetOrCreate(chan);
			if (store.values.empty())
				store.values.reserve(limits.maxkeys);

			if (store.values.size() >= limits.maxkeys && store.values.find(key) == store.values.end())
			{
				parent.SendFail(lu, this, "LIMIT_REACHED", chan->name, "metadata limit reached");
				return CmdResult::FAILURE;
			}

			store.values[key] = value;
			parent.SendKeyValue(lu, chan->name, key, parent.GetVisibility(user, key, chan->name), value, nullptr);
			parent.NotifyChanMetadataChange(chan, key, value);
			return CmdResult::SUCCESS;
		}
		else
		{
			User* tgtuser = (target == "*") ? user : ServerInstance->Users.FindNick(target, true);
			if (!tgtuser)
			{
				parent.SendFail(lu, this, "INVALID_TARGET", target, "invalid metadata target");
				return CmdResult::FAILURE;
			}
			if (!parent.CanWriteUserMetadata(user, tgtuser))
			{
				parent.SendFail(lu, this, "KEY_NO_PERMISSION", tgtuser->nick, key, "permission denied");
				return CmdResult::FAILURE;
			}
			if (!parent.CanSetMetadata(user, key, tgtuser->nick))
			{
				parent.SendFail(lu, this, "KEY_NO_PERMISSION", tgtuser->nick, key, "permission denied");
				return CmdResult::FAILURE;
			}
			if (!parent.CheckRateLimit(lu, this, tgtuser->nick, key))
				return CmdResult::FAILURE;

			if (!hasvalue)
			{
				MetadataStore* store = parent.usermeta.Get(tgtuser);
				if (!store)
				{
					parent.SendFail(lu, this, "KEY_NOT_SET", tgtuser->nick, key, "key not set");
					return CmdResult::FAILURE;
				}
				auto it = store->values.find(key);
				if (it == store->values.end())
				{
					parent.SendFail(lu, this, "KEY_NOT_SET", tgtuser->nick, key, "key not set");
					return CmdResult::FAILURE;
				}
				store->values.erase(it);
				if (store->values.empty())
					parent.usermeta.Unset(tgtuser);
				parent.SendKeyNotSet(lu, tgtuser->nick, key, nullptr);
				parent.NotifyUserMetadataChange(tgtuser, key, std::string());
				return CmdResult::SUCCESS;
			}

			MetadataStore& store = parent.usermeta.GetOrCreate(tgtuser);
			if (store.values.empty())
				store.values.reserve(limits.maxkeys);

			if (store.values.size() >= limits.maxkeys && store.values.find(key) == store.values.end())
			{
				parent.SendFail(lu, this, "LIMIT_REACHED", tgtuser->nick, "metadata limit reached");
				return CmdResult::FAILURE;
			}
			store.values[key] = value;
			parent.SendKeyValue(lu, tgtuser->nick, key, parent.GetVisibility(user, key, tgtuser->nick), value, nullptr);
			parent.NotifyUserMetadataChange(tgtuser, key, value);
			return CmdResult::SUCCESS;
		}
	}
	else if (irc::equals(subcmd, "CLEAR"))
	{
		Extensible* ext = nullptr;
		std::string targetname = target;
		MetadataExt* metaext = nullptr;
		bool ischan = false;
		Channel* chan = nullptr;
		User* tgtuser = nullptr;

		if (!target.empty() && target[0] == '#')
		{
			chan = ServerInstance->Channels.Find(target);
			if (!chan)
			{
				parent.SendFail(lu, this, "INVALID_TARGET", target, "invalid metadata target");
				return CmdResult::FAILURE;
			}
			if (!parent.CanWriteChanMetadata(user, chan))
			{
				parent.SendFail(lu, this, "KEY_NO_PERMISSION", chan->name, "*", "permission denied");
				return CmdResult::FAILURE;
			}
			ext = chan;
			metaext = &parent.chanmeta;
			ischan = true;
		}
		else
		{
			tgtuser = (target == "*") ? user : ServerInstance->Users.FindNick(target, true);
			if (!tgtuser)
			{
				parent.SendFail(lu, this, "INVALID_TARGET", target, "invalid metadata target");
				return CmdResult::FAILURE;
			}
			if (!parent.CanWriteUserMetadata(user, tgtuser))
			{
				parent.SendFail(lu, this, "KEY_NO_PERMISSION", tgtuser->nick, "*", "permission denied");
				return CmdResult::FAILURE;
			}
			ext = tgtuser;
			metaext = &parent.usermeta;
			targetname = tgtuser->nick;
		}

		MetadataStore* store = metaext->Get(ext);

		IRCv3::Batch::Batch batch("metadata");
		IRCv3::Batch::Batch* batchptr = nullptr;
		if (parent.batchmanager && parent.batchcap.IsEnabled(lu))
		{
			parent.SendMetadataBatchStart(lu, batch, targetname);
			batchptr = &batch;
		}

		if (store)
		{
			auto oldvalues = std::move(store->values);
			metaext->Unset(ext);
			for (const auto& [key, value] : oldvalues)
			{
				if (!parent.CanReadMetadata(user, key, targetname))
				{
					parent.SendFail(lu, this, "KEY_NO_PERMISSION", targetname, key, "permission denied");
					continue;
				}
				parent.SendKeyValue(lu, targetname, key, parent.GetVisibility(user, key, targetname), value, batchptr);
				if (ischan)
					parent.NotifyChanMetadataChange(chan, key, std::string());
				else
					parent.NotifyUserMetadataChange(tgtuser, key, std::string());
			}
		}

		if (batchptr)
			parent.SendMetadataBatchEnd(batch);
		return CmdResult::SUCCESS;
	}
	else if (irc::equals(subcmd, "SYNC"))
	{
		const auto& limits = parent.cap.GetLimits(lu);

		// Send subscribed metadata for the requested target.
		MetadataSubs* s = parent.subs.Get(lu);
		if (!s || s->keys.empty())
		{
			// Still return an empty batch if batch is enabled.
			if (parent.batchmanager && parent.batchcap.IsEnabled(lu))
			{
				IRCv3::Batch::Batch batch("metadata");
				parent.SendMetadataBatchStart(lu, batch, target);
				parent.SendMetadataBatchEnd(batch);
			}
			return CmdResult::SUCCESS;
		}

		IRCv3::Batch::Batch batch("metadata");
		IRCv3::Batch::Batch* batchptr = nullptr;
		if (parent.batchmanager && parent.batchcap.IsEnabled(lu))
		{
			parent.SendMetadataBatchStart(lu, batch, target);
			batchptr = &batch;
		}

		if (!target.empty() && target[0] == '#')
		{
			Channel* chan = ServerInstance->Channels.Find(target);
			if (!chan)
			{
				parent.SendFail(lu, this, "INVALID_TARGET", target, "invalid metadata target");
				if (batchptr)
					parent.SendMetadataBatchEnd(batch);
				return CmdResult::FAILURE;
			}

			if (parent.ShouldPostponeSync(lu, chan))
			{
				if (batchptr)
					parent.SendMetadataBatchEnd(batch);
				parent.SendSyncLater(lu, chan->name, limits.syncretryafter);
				return CmdResult::SUCCESS;
			}

			parent.SyncToUser(lu, chan->name, parent.chanmeta.Get(chan), s, batchptr);
			for (const auto& [memberuser, member] : chan->GetUsers())
				parent.SyncToUser(lu, memberuser->nick, parent.usermeta.Get(memberuser), s, batchptr);
		}
		else
		{
			User* tgtuser = (target == "*") ? user : ServerInstance->Users.FindNick(target, true);
			if (!tgtuser)
			{
				parent.SendFail(lu, this, "INVALID_TARGET", target, "invalid metadata target");
				if (batchptr)
					parent.SendMetadataBatchEnd(batch);
				return CmdResult::FAILURE;
			}
			parent.SyncToUser(lu, tgtuser->nick, parent.usermeta.Get(tgtuser), s, batchptr);
		}

		if (batchptr)
			parent.SendMetadataBatchEnd(batch);
		return CmdResult::SUCCESS;
	}
	else if (irc::equals(target, "*") && irc::equals(subcmd, "SUB"))
	{
		if (parameters.size() < 3)
			return CmdResult::INVALID;

		const auto& limits = parent.cap.GetLimits(lu);

		MetadataSubs& s = parent.subs.GetRef(lu);
		if (s.keys.empty())
			s.keys.reserve(limits.maxsubs);
		std::vector<std::string> ok;
		for (size_t idx = 2; idx < parameters.size(); ++idx)
		{
			const std::string& key = parameters[idx];
			if (!IsValidMetadataKey(key))
			{
				parent.SendFail(lu, this, "KEY_INVALID", key, "invalid key");
				continue;
			}

			if (s.keys.size() >= limits.maxsubs && s.keys.find(key) == s.keys.end())
			{
				parent.SendFail(lu, this, "TOO_MANY_SUBS", key, "too many subscriptions");
				break;
			}

			s.keys.emplace(key);
			ok.push_back(key);
		}

		if (!ok.empty())
		{
			Numeric::Numeric n(RPL_METADATASUBOK);
			for (const auto& k : ok)
				n.push(k);
			lu->WriteNumeric(n);
		}
		return CmdResult::SUCCESS;
	}
	else if (irc::equals(target, "*") && irc::equals(subcmd, "UNSUB"))
	{
		if (parameters.size() < 3)
			return CmdResult::INVALID;

		MetadataSubs* s = parent.subs.Get(lu);
		std::vector<std::string> ok;
		for (size_t idx = 2; idx < parameters.size(); ++idx)
		{
			const std::string& key = parameters[idx];
			if (!IsValidMetadataKey(key))
			{
				parent.SendFail(lu, this, "KEY_INVALID", key, "invalid key");
				continue;
			}
			if (s)
				s->keys.erase(key);
			ok.push_back(key);
		}

		if (s && s->keys.empty())
			parent.subs.Unset(lu);

		if (!ok.empty())
		{
			Numeric::Numeric n(RPL_METADATAUNSUBOK);
			for (const auto& k : ok)
				n.push(k);
			lu->WriteNumeric(n);
		}
		return CmdResult::SUCCESS;
	}
	else if (irc::equals(target, "*") && irc::equals(subcmd, "SUBS"))
	{
		MetadataSubs* s = parent.subs.Get(lu);
		if (!s || s->keys.empty())
			return CmdResult::SUCCESS;

		IRCv3::Batch::Batch batch("metadata-subs");
		IRCv3::Batch::Batch* batchptr = nullptr;
		if (parent.batchmanager && parent.batchcap.IsEnabled(lu))
		{
			parent.batchmanager->Start(batch);
			batchptr = &batch;
		}

		// Send all keys in one numeric; clients must accept multiple numerics but not required.
		Numeric::Numeric n(RPL_METADATASUBS);
		for (const auto& key : s->keys)
			n.push(key);
		if (batchptr && batchptr->IsRunning() && parent.batchmanager)
			n.AddTag("batch", parent.batchmanager.operator->(), batchptr->GetRefTagStr(), batchptr);
		lu->WriteNumeric(n);

		if (batchptr)
			parent.batchmanager->End(batch);
		return CmdResult::SUCCESS;
	}

	parent.SendFail(lu, this, "SUBCOMMAND_INVALID", subcmd, "invalid subcommand");
	return CmdResult::FAILURE;
}

MODULE_INIT(ModuleIRCv3Metadata)
