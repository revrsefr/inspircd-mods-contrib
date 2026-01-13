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
/// $ModDesc: Persists IRCv3 draft/metadata-2 user/channel metadata to disk.
/// $ModConfig: <module name="m_ircv3_metadata_db">
/// $ModConfig: <ircv3metadatadb filename="metadata.db" saveperiod="300" backoff="0" maxbackoff="36000" expireafter="0" users="yes" channels="permanent" maxuserentries="50000" maxchanentries="5000">



#include "inspircd.h"
#include "extension.h"
#include "modules/account.h"
#include "timeutils.h"
#include <filesystem>
#include <fstream>
#include <vector>
#include <system_error>
#include <unordered_map>
#include <unordered_set>

namespace
{
	enum class ChanPolicy
	{
		NONE,
		PERMANENT,
		ALL,
	};

	struct Entry final
	{
		time_t updated = 0;
		std::string internal;
	};

	std::string GetInternal(const Extensible* ext, ExtensionItem* item)
	{
		if (!ext || !item)
			return {};

		const auto& exts = ext->GetExtList();
		auto it = exts.find(item);
		if (it == exts.end())
			return {};

		return item->ToInternal(ext, it->second);
	}

	bool IsExpired(time_t now, const Entry& entry, unsigned long expireafter)
	{
		if (!expireafter)
			return false;
		if (!entry.updated)
			return false;
		return (now > entry.updated) && (static_cast<unsigned long>(now - entry.updated) > expireafter);
	}
}

class ModuleIRCv3MetadataDB final
	: public Module
	, public Timer
	, public Account::EventListener
{
private:
	Account::API accountapi;

	ExtensionItem* usermeta = nullptr;
	ExtensionItem* chanmeta = nullptr;

	bool dirty = false;
	bool loaded = false;

	std::string dbpath;
	unsigned long saveperiod = 300;
	unsigned long expireafter = 0;
	unsigned long maxbackoff = 0;
	unsigned char backoff = 0;

	size_t maxuserentries = 0;
	size_t maxchanentries = 0;

	bool persistusers = true;
	ChanPolicy persistchans = ChanPolicy::PERMANENT;

	std::unordered_map<std::string, Entry> userdb;
	std::unordered_map<std::string, Entry> chandb;

	static bool IsMetadataModule(const Module* mod)
	{
		// ModuleFile is the expanded module filename (e.g. "m_foo.so").
		return mod && insp::equalsci(mod->ModuleFile, "m_ircv3_metadata.so");
	}

	void ResolveExtensions()
	{
		usermeta = ServerInstance->Extensions.GetItem("metadata-user");
		chanmeta = ServerInstance->Extensions.GetItem("metadata-chan");

		if (usermeta && usermeta->extype != ExtensionType::USER)
			usermeta = nullptr;
		if (chanmeta && chanmeta->extype != ExtensionType::CHANNEL)
			chanmeta = nullptr;
	}

	bool IsChanPersistable(const Channel* chan) const
	{
		if (!chan)
			return false;

		switch (persistchans)
		{
			case ChanPolicy::NONE:
				return false;
			case ChanPolicy::ALL:
				return true;
			case ChanPolicy::PERMANENT:
			{
				ModeHandler* pm = ServerInstance->Modes.FindMode('P', MODETYPE_CHANNEL);
				return pm && chan->IsModeSet(pm);
			}
		}
		return false;
	}

	void PruneExpired(time_t now)
	{
		if (!expireafter)
			return;

		for (auto it = userdb.begin(); it != userdb.end(); )
		{
			if (IsExpired(now, it->second, expireafter))
			{
				it = userdb.erase(it);
				dirty = true;
				continue;
			}
			++it;
		}

		for (auto it = chandb.begin(); it != chandb.end(); )
		{
			if (IsExpired(now, it->second, expireafter))
			{
				it = chandb.erase(it);
				dirty = true;
				continue;
			}
			++it;
		}
	}

	void PruneToMaxEntries(std::unordered_map<std::string, Entry>& db, size_t maxentries)
	{
		if (!maxentries)
			return;
		if (db.size() <= maxentries)
			return;

		std::vector<std::pair<time_t, std::string>> order;
		order.reserve(db.size());
		for (const auto& [key, entry] : db)
			order.emplace_back(entry.updated, key);

		std::sort(order.begin(), order.end(), [](const auto& a, const auto& b) {
			// Oldest first; treat 0 as oldest.
			if (a.first != b.first)
				return a.first < b.first;
			return a.second < b.second;
		});

		const size_t drop = db.size() - maxentries;
		for (size_t i = 0; i < drop; ++i)
		{
			auto it = db.find(order[i].second);
			if (it != db.end())
				db.erase(it);
		}

		dirty = true;
	}

	void PruneToLimits()
	{
		if (maxuserentries)
			PruneToMaxEntries(userdb, maxuserentries);
		if (maxchanentries)
			PruneToMaxEntries(chandb, maxchanentries);
	}

	void CleanupTempFiles()
	{
		if (dbpath.empty())
			return;

		std::error_code ec;
		const std::filesystem::path base(dbpath);
		const auto parent = base.parent_path();
		if (parent.empty())
			return;

		const std::string prefix = dbpath + ".new.";
		size_t removed = 0;
		for (const auto& dent : std::filesystem::directory_iterator(parent, ec))
		{
			if (ec)
				break;

			const auto& path = dent.path();
			const std::string full = path.string();
			if (full.rfind(prefix, 0) != 0)
				continue;

			std::filesystem::remove(path, ec);
			if (!ec)
				removed++;
		}

		if (removed)
			ServerInstance->Logs.Normal(MODNAME, "Removed {} stale temp database file(s) for {}", removed, dbpath);
	}

	void RefreshFromOnline(time_t now)
	{
		if (persistusers && usermeta && accountapi)
		{
			std::unordered_set<std::string> seenaccounts;
			for (const auto& [_, user] : ServerInstance->Users.GetUsers())
			{
				const std::string* accountname = accountapi->GetAccountName(user);
				if (!accountname || accountname->empty())
					continue;

				seenaccounts.insert(*accountname);

				const std::string internal = GetInternal(user, usermeta);
				auto it = userdb.find(*accountname);

				if (internal.empty())
				{
					if (it != userdb.end())
					{
						userdb.erase(it);
						dirty = true;
					}
					continue;
				}

				if (it == userdb.end())
				{
					userdb.emplace(*accountname, Entry{ now, internal });
					dirty = true;
					continue;
				}

				if (it->second.internal != internal)
				{
					it->second.internal = internal;
					it->second.updated = now;
					dirty = true;
				}
			}

			// Remove entries for accounts that are no longer online if they have no persisted data.
			// We keep offline accounts in the DB so metadata persists across reconnects.
			(void)seenaccounts;
		}

		if (persistchans != ChanPolicy::NONE && chanmeta)
		{
			std::unordered_set<std::string> seenchans;
			for (const auto& [_, chan] : ServerInstance->Channels.GetChans())
			{
				if (!IsChanPersistable(chan))
					continue;

				seenchans.insert(chan->name);

				const std::string internal = GetInternal(chan, chanmeta);
				auto it = chandb.find(chan->name);

				if (internal.empty())
				{
					if (it != chandb.end())
					{
						chandb.erase(it);
						dirty = true;
					}
					continue;
				}

				if (it == chandb.end())
				{
					chandb.emplace(chan->name, Entry{ now, internal });
					dirty = true;
					continue;
				}

				if (it->second.internal != internal)
				{
					it->second.internal = internal;
					it->second.updated = now;
					dirty = true;
				}
			}

			// Drop entries for channels that no longer exist.
			for (auto it = chandb.begin(); it != chandb.end(); )
			{
				if (seenchans.find(it->first) == seenchans.end())
				{
					it = chandb.erase(it);
					dirty = true;
					continue;
				}
				++it;
			}
		}
	}

	void ApplyChannelIfPresent(const std::string& name, const Entry& entry)
	{
		if (!chanmeta)
			return;

		Channel* chan = ServerInstance->Channels.Find(name);
		if (!chan)
			return;
		if (!IsChanPersistable(chan))
			return;

		chanmeta->FromInternal(chan, entry.internal);
	}

	void ApplyUserIfPresent(User* user, const std::string& account)
	{
		if (!usermeta)
			return;
		if (account.empty())
			return;

		auto it = userdb.find(account);
		if (it == userdb.end())
			return;

		usermeta->FromInternal(user, it->second.internal);
	}

	void ApplyAllToOnline()
	{
		if (persistusers && usermeta && accountapi)
		{
			for (const auto& [_, user] : ServerInstance->Users.GetUsers())
			{
				const std::string* accountname = accountapi->GetAccountName(user);
				if (!accountname || accountname->empty())
					continue;

				ApplyUserIfPresent(user, *accountname);
			}
		}

		if (persistchans != ChanPolicy::NONE && chanmeta)
		{
			for (const auto& [name, entry] : chandb)
				ApplyChannelIfPresent(name, entry);
		}
	}

	void MirrorUserNow(User* user, time_t now)
	{
		if (!persistusers || !usermeta || !accountapi || !user)
			return;

		const std::string* accountname = accountapi->GetAccountName(user);
		if (!accountname || accountname->empty())
			return;

		const std::string internal = GetInternal(user, usermeta);
		if (internal.empty())
		{
			auto it = userdb.find(*accountname);
			if (it != userdb.end())
			{
				userdb.erase(it);
				dirty = true;
			}
			return;
		}

		auto it = userdb.find(*accountname);
		if (it == userdb.end())
		{
			userdb.emplace(*accountname, Entry{ now, internal });
			dirty = true;
			return;
		}

		if (it->second.internal != internal)
		{
			it->second.internal = internal;
			it->second.updated = now;
			dirty = true;
		}
	}

	void MirrorChannelNow(Channel* chan, time_t now)
	{
		if (persistchans == ChanPolicy::NONE || !chanmeta || !chan)
			return;
		if (!IsChanPersistable(chan))
			return;

		const std::string internal = GetInternal(chan, chanmeta);
		if (internal.empty())
		{
			auto it = chandb.find(chan->name);
			if (it != chandb.end())
			{
				chandb.erase(it);
				dirty = true;
			}
			return;
		}

		auto it = chandb.find(chan->name);
		if (it == chandb.end())
		{
			chandb.emplace(chan->name, Entry{ now, internal });
			dirty = true;
			return;
		}

		if (it->second.internal != internal)
		{
			it->second.internal = internal;
			it->second.updated = now;
			dirty = true;
		}
	}

	void ReadDatabase()
	{
		if (dbpath.empty())
			return;

		std::ifstream stream(dbpath);
		if (!stream.is_open())
			return;

		userdb.clear();
		chandb.clear();

		std::string line;
		time_t now = ServerInstance->Time();
		while (std::getline(stream, line))
		{
			if (line.empty() || line[0] == '#')
				continue;

			irc::spacesepstream iss(line);
			std::string type;
			if (!iss.GetToken(type) || type.size() != 1)
				continue;

			std::string updatedstr;
			std::string targetb64;
			std::string datab64;
			if (!iss.GetToken(updatedstr) || !iss.GetToken(targetb64) || !iss.GetToken(datab64))
				continue;

			time_t updated = ConvToNum<time_t>(updatedstr);
			if (updated < 0)
				updated = 0;

			Entry entry;
			entry.updated = updated;
			entry.internal = Base64::Decode(datab64);
			if (entry.internal.empty())
				continue;

			if (IsExpired(now, entry, expireafter))
				continue;

			const std::string target = Base64::Decode(targetb64);
			if (target.empty())
				continue;

			switch (type[0])
			{
				case 'U':
					userdb[target] = std::move(entry);
					break;
				case 'C':
					chandb[target] = std::move(entry);
					break;
				default:
					break;
			}
		}

		// Apply channel metadata to channels that already exist.
		if (persistchans != ChanPolicy::NONE && chanmeta)
		{
			for (const auto& [name, entry] : chandb)
				ApplyChannelIfPresent(name, entry);
		}

		PruneToLimits();

		dirty = false;
	}

	bool WriteDatabase()
	{
		if (dbpath.empty())
			return true;

		// Ensure the parent directory exists (e.g. when filename contains subdirectories).
		{
			std::error_code ec;
			const auto parent = std::filesystem::path(dbpath).parent_path();
			if (!parent.empty())
				std::filesystem::create_directories(parent, ec);
		}

		const auto newpath = INSP_FORMAT("{}.new.{}", dbpath, ServerInstance->Time());
		std::ofstream stream(newpath);
		if (!stream.is_open())
		{
			ServerInstance->Logs.Critical(MODNAME, "Cannot create database \"{}\"! {} ({})", newpath, strerror(errno), errno);
			ServerInstance->SNO.WriteToSnoMask('a', "database: cannot create new ircv3 metadata db \"{}\": {} ({})", newpath, strerror(errno), errno);
			return false;
		}

		stream
			<< "# This file was automatically generated by the " << INSPIRCD_VERSION << " ircv3 metadata db module on "
			<< Time::ToString(ServerInstance->Time()) << "." << std::endl
			<< "# Any changes to this file will be automatically overwritten." << std::endl
			<< std::endl;

		for (const auto& [account, entry] : userdb)
		{
			if (entry.internal.empty())
				continue;
			stream
				<< 'U' << ' ' << entry.updated << ' '
				<< Base64::Encode(account) << ' '
				<< Base64::Encode(entry.internal)
				<< std::endl;
		}

		for (const auto& [channame, entry] : chandb)
		{
			if (entry.internal.empty())
				continue;
			stream
				<< 'C' << ' ' << entry.updated << ' '
				<< Base64::Encode(channame) << ' '
				<< Base64::Encode(entry.internal)
				<< std::endl;
		}

		stream.close();
		if (stream.fail())
		{
			ServerInstance->Logs.Critical(MODNAME, "Cannot write database \"{}\"! {} ({})", newpath, strerror(errno), errno);
			ServerInstance->SNO.WriteToSnoMask('a', "database: cannot write ircv3 metadata db \"{}\": {} ({})", newpath, strerror(errno), errno);
			std::error_code ec;
			std::filesystem::remove(newpath, ec);
			return false;
		}

#ifdef _WIN32
	remove(dbpath.c_str());
#endif
	if (rename(newpath.c_str(), dbpath.c_str()) < 0)
	{
		ServerInstance->Logs.Critical(MODNAME, "Cannot replace old database \"{}\" with new database \"{}\"! {} ({})", dbpath, newpath, strerror(errno), errno);
		ServerInstance->SNO.WriteToSnoMask('a', "database: cannot replace old ircv3 metadata db \"{}\" with new db \"{}\": {} ({})", dbpath, newpath, strerror(errno), errno);
			std::error_code ec;
			std::filesystem::remove(newpath, ec);
		return false;
	}

	return true;
	}

public:
	ModuleIRCv3MetadataDB()
		: Module(VF_VENDOR, "Persists IRCv3 draft/metadata-2 user/channel metadata to disk.")
		, Timer(0, true)
		, Account::EventListener(this)
		, accountapi(this)
	{
	}

	void init() override
	{
		const auto& Conf = ServerInstance->Config->ConfValue("ircv3metadatadb");

		dbpath = Conf->getString("filename", "metadata.db", 1);
		if (!dbpath.empty())
			dbpath = ServerInstance->Config->Paths.PrependData(dbpath);

		saveperiod = Conf->getDuration("saveperiod", 300, 5);
		backoff = Conf->getNum<uint8_t>("backoff", 0);
		maxbackoff = Conf->getDuration("maxbackoff", saveperiod * 120, saveperiod);
		SetInterval(saveperiod);

		expireafter = Conf->getDuration("expireafter", 0);
		maxuserentries = Conf->getNum<size_t>("maxuserentries", 0);
		maxchanentries = Conf->getNum<size_t>("maxchanentries", 0);
		persistusers = Conf->getBool("users", true);

		const std::string chanpol = Conf->getString("channels", "permanent");
		if (insp::equalsci(chanpol, "none"))
			persistchans = ChanPolicy::NONE;
		else if (insp::equalsci(chanpol, "all"))
			persistchans = ChanPolicy::ALL;
		else
			persistchans = ChanPolicy::PERMANENT;

		ResolveExtensions();
		ReadDatabase();
		CleanupTempFiles();

		// If the database file doesn't exist yet, create an empty one immediately so
		// it's visible to admins and ready for future writes.
		if (!dbpath.empty())
		{
			std::error_code ec;
			const bool exists = std::filesystem::exists(dbpath, ec);
			const auto size = exists ? std::filesystem::file_size(dbpath, ec) : 0;
			if (!exists || (!ec && size == 0))
				(void)WriteDatabase();
		}

		loaded = true;
		dirty = false;
	}

	void Prioritize() override
	{
		// Ensure we can find extensions even if m_ircv3_metadata is loaded after us.
		ResolveExtensions();
		if (!loaded)
			return;

		// Apply channel data to any channels created by other modules after init.
		if (persistchans != ChanPolicy::NONE && chanmeta)
		{
			for (const auto& [name, entry] : chandb)
				ApplyChannelIfPresent(name, entry);
		}
	}

	void OnUserJoin(Membership* memb, bool sync, bool created, CUList&) override
	{
		(void)sync;
		if (!created)
			return;
		if (persistchans == ChanPolicy::NONE)
			return;

		const auto it = chandb.find(memb->chan->name);
		if (it == chandb.end())
			return;

		ApplyChannelIfPresent(memb->chan->name, it->second);
	}

	void OnAccountChange(User* user, const std::string& account) override
	{
		if (!persistusers)
			return;
		if (!accountapi)
			return;

		if (!account.empty())
			ApplyUserIfPresent(user, account);
	}

	void OnLoadModule(Module* mod) override
	{
		// When m_ircv3_metadata is (re)loaded it recreates its extension items,
		// wiping the in-memory metadata. Re-resolve and reapply from our DB.
		if (!loaded)
			return;
		if (!IsMetadataModule(mod))
			return;

		ServerInstance->Logs.Normal(MODNAME, "Detected {} load; reapplying persisted metadata", mod->ModuleFile);

		ResolveExtensions();
		ApplyAllToOnline();
	}

	void OnUnloadModule(Module* mod) override
	{
		// m_ircv3_metadata unregisters its extension items during unload; drop
		// our pointers so we don't keep dangling references.
		if (!IsMetadataModule(mod))
			return;

		usermeta = nullptr;
		chanmeta = nullptr;
	}

	void OnPostCommand(Command* command, const CommandBase::Params& parameters, LocalUser* user, CmdResult result, bool loop) override
	{
		if (loop)
			return;
		if (result != CmdResult::SUCCESS)
			return;
		if (!loaded)
			return;
		if (!command || !insp::equalsci(command->name, "METADATA"))
			return;
		if (parameters.size() < 2)
			return;

		const std::string& subcmd = parameters[1];
		if (!insp::equalsci(subcmd, "SET") && !insp::equalsci(subcmd, "CLEAR"))
			return;
		if (dbpath.empty())
			return;

		ResolveExtensions();
		time_t now = ServerInstance->Time();

		// Mirror the current state immediately so module reloads don't lose changes
		// during the saveperiod window.
		const std::string& rawtarget = parameters[0];
		if (!rawtarget.empty() && rawtarget[0] == '#')
		{
			Channel* chan = ServerInstance->Channels.Find(rawtarget);
			if (chan)
				MirrorChannelNow(chan, now);
		}
		else
		{
			std::string target = rawtarget;
			if (target == "*")
				target = user ? user->nick : "*";
			User* tgt = (target == "*") ? user : ServerInstance->Users.FindNick(target, true);
			if (tgt)
				MirrorUserNow(tgt, now);
		}

		if (dirty)
		{
			if (WriteDatabase())
				dirty = false;
		}
	}

	bool Tick() override
	{
		if (dbpath.empty())
			return true;

		ResolveExtensions();
		time_t now = ServerInstance->Time();

		PruneExpired(now);
		RefreshFromOnline(now);
		PruneToLimits();

		if (dirty)
		{
			if (WriteDatabase())
			{
				if (GetInterval() != saveperiod)
					SetInterval(saveperiod, false);
				dirty = false;
			}
			else
			{
				if (backoff > 1)
					SetInterval(std::min(GetInterval() * backoff, maxbackoff), false);
				ServerInstance->Logs.Debug(MODNAME, "Trying again in {}", Duration::ToLongString(GetInterval()));
			}
		}

		return true;
	}
};

MODULE_INIT(ModuleIRCv3MetadataDB)
