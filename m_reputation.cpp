/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   (C) 2026 reverse - mike.chevronnet@gmail.com
 *
 * Provides a reputation scoring system for IP addresses.
 *
 * Every bump interval (default: 5 minutes) connected users cause their IP
 * reputation score to increase by +1; if the user is logged into services then
 * an additional point is applied (+2 total per interval).
 *
 * Configuration example:
 *
 *   <reputation
 *     database="reputation.db"
 *     ipv4prefix="32"
 *     ipv6prefix="64"
 *     bumpinterval="5m"
 *     expireinterval="605"
 *     saveinterval="902"
 *     minchanmembers="3"
 *     scorecap="10000"
 *     whois="all">
 *
 * Exposes:
 * - user extension "reputation" (per-user score, synced to local users)
 * - /REPUTATION command (operator-only)
 * - extended ban "score" e.g. +b score:<100 (ban users with score < 100), +b score:>100 (ban users with score > 100)
 */

/// $ModAuthor: reverse - mike.chevronnet@gmail.com
/// $ModDepends: core 4
/// $ModDesc: Tracks IP reputation and provides a score-based extban.
/// $ModConfig: <reputation database="reputation.db" ipv4prefix="32" ipv6prefix="64" bumpinterval="5m" expireinterval="605" saveinterval="902" minchanmembers="3" scorecap="10000" whois="all">


#include "inspircd.h"
#include "extension.h"
#include "numerichelper.h"
#include "modules/extban.h"
#include "modules/account.h"
#include "modules/whois.h"
#include "timeutils.h"
#include <cstdio>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace
{
	constexpr uint16_t DEFAULT_SCORE_CAP = 10000;
	constexpr unsigned long DEFAULT_BUMP_INTERVAL = 300;
	constexpr unsigned long DEFAULT_EXPIRE_INTERVAL = 605;
	constexpr unsigned long DEFAULT_SAVE_INTERVAL = 902;

	struct ExpireRule final
	{
		int score = -1;
		unsigned long age = 0;
	};

	struct ReputationEntry final
	{
		uint16_t score = 0;
		time_t last_seen = 0;
		uint32_t marker = 0;
	};

	enum class WhoisVisibility
	{
		NONE,
		SELF,
		OPERS,
		ALL,
	};

	bool LooksLikeIP(const std::string& text)
	{
		return text.find_first_of(".:") != std::string::npos;
	}

	bool TryParseULong(const std::string& text, unsigned long& out)
	{
		std::istringstream iss(text);
		unsigned long value = 0;
		if (!(iss >> value))
			return false;
		char junk;
		if (iss >> junk)
			return false;
		out = value;
		return true;
	}
}

class ModuleReputation;

class ReputationScoreExtBan final
	: public ExtBan::MatchingBase
{
private:
	IntExtItem& repouserext;

public:
	ReputationScoreExtBan(Module* Creator, IntExtItem& rep)
		: ExtBan::MatchingBase(Creator, "score", 'y')
		, repouserext(rep)
	{
	}

	void Canonicalize(std::string& text) override
	{
		// Allow score:<100 as a more readable form.
		// Note: we do not strip '>' because it changes the meaning.
		if (!text.empty() && text.front() == '<')
			text.erase(text.begin());
	}

	bool IsMatch(User* user, Channel* channel, const std::string& text) override
	{
		std::string parsed = text;

		// Default to the legacy behavior (treat as score:<N).
		const bool gt = (!parsed.empty() && parsed.front() == '>');
		if (!parsed.empty() && (parsed.front() == '<' || parsed.front() == '>'))
			parsed.erase(parsed.begin());

		unsigned long threshold = 0;
		if (parsed.empty() || !TryParseULong(parsed, threshold))
			return false;

		const auto score = static_cast<unsigned long>(std::max<intptr_t>(0, repouserext.Get(user)));
		return gt ? (score > threshold) : (score < threshold);
	}
};

class ReputationTimer final
	: public Timer
{
public:
	enum class Type
	{
		BUMP,
		EXPIRE,
		SAVE,
	};

private:
	ModuleReputation& parent;
	const Type type;

public:
	ReputationTimer(ModuleReputation& Parent, Type timer, unsigned long interval)
		: Timer(interval, true)
		, parent(Parent)
		, type(timer)
	{
	}

	bool Tick() override;
};

class CommandReputation final
	: public Command
{
private:
	ModuleReputation& parent;

public:
	CommandReputation(Module* Creator, ModuleReputation& Parent);
	CmdResult Handle(User* user, const Params& parameters) override;
	RouteDescriptor GetRouting(User* user, const Params& parameters) override;
};

class ModuleReputation final
	: public Module
	, public Whois::EventListener
{
	friend class ReputationTimer;
	friend class CommandReputation;

private:
	Account::API accountapi;
	IntExtItem repouserext;
	ReputationScoreExtBan scoreextban;
	CommandReputation cmd;

	insp::flat_map<std::string, ReputationEntry> entries;
	std::vector<ExpireRule> rules;

	std::string dbpath;

	unsigned long bumpinterval = DEFAULT_BUMP_INTERVAL;
	unsigned long expireinterval = DEFAULT_EXPIRE_INTERVAL;
	unsigned long saveinterval = DEFAULT_SAVE_INTERVAL;
	unsigned long minchanmembers = 3;
	uint16_t scorecap = DEFAULT_SCORE_CAP;
	unsigned char ipv4prefix = 32;
	unsigned char ipv6prefix = 64;
	WhoisVisibility whoisvis = WhoisVisibility::ALL;

	ReputationTimer bumptimer;
	ReputationTimer expiretimer;
	ReputationTimer savetimer;

	time_t starttime = 0;
	time_t writtentime = 0;
	bool dirty = false;
	uint32_t markerepoch = 0;

	void MarkUpsert(const std::string&)
	{
		dirty = true;
	}

	void MarkDelete(const std::string&)
	{
		dirty = true;
	}

	unsigned long GetHighestChannelMemberCount(User* user) const
	{
		unsigned long maxcount = 0;
		for (auto* memb : user->chans)
			maxcount = std::max<unsigned long>(maxcount, memb->chan->GetUsers().size());
		return maxcount;
	}

	std::string NormaliseReputationKey(const irc::sockets::sockaddrs& sa) const
	{
		if (!sa.is_ip())
			return "";

		// If the client connected via an IPv6 socket but is actually IPv4 then the
		// address may be a v4-mapped IPv6 address (::ffff:0:0/96). Treat these as
		// IPv4 so ipv4prefix applies and we don't accidentally group unrelated IPv4
		// users by ipv6prefix.
		if (sa.family() == AF_INET6)
		{
			const auto& a = sa.in6.sin6_addr.s6_addr;
			static constexpr unsigned char V4MAP_PREFIX[12] = { 0,0,0,0,0,0,0,0,0,0,0xFF,0xFF };
			if (!memcmp(a, V4MAP_PREFIX, sizeof(V4MAP_PREFIX)))
			{
				irc::sockets::sockaddrs v4(false);
				v4.in4.sin_family = AF_INET;
				v4.in4.sin_port = 0;
				memcpy(&v4.in4.sin_addr, a + 12, 4);
				const unsigned char prefix = std::min<unsigned char>(ipv4prefix, 32);
				return irc::sockets::cidr_mask(v4, prefix).str();
			}
		}

		const unsigned char maxlen = sa.family() == AF_INET ? 32 : 128;
		unsigned char prefix = sa.family() == AF_INET ? ipv4prefix : ipv6prefix;
		if (prefix > maxlen)
			prefix = maxlen;
		return irc::sockets::cidr_mask(sa, prefix).str();
	}

	std::string NormaliseReputationKey(const std::string& address) const
	{
		// Accept plain IPs as well as CIDR strings.
		std::string ip = address;
		const auto slashpos = ip.find('/');
		if (slashpos != std::string::npos)
			ip.erase(slashpos);

		irc::sockets::sockaddrs sa;
		if (!sa.from_ip(ip))
			return "";

		return NormaliseReputationKey(sa);
	}

	std::string GetReputationKey(User* user) const
	{
		// Local users always have a real socket address.
		if (user->client_sa.is_ip())
			return NormaliseReputationKey(user->client_sa);

		// Remote users may not have a usable sockaddrs representation; fall back to
		// their textual address so ENCAP updates and extbans stay consistent.
		const std::string& address = user->GetAddress();
		if (address.empty())
			return "";
		return NormaliseReputationKey(address);
	}

	ReputationEntry* FindEntry(const std::string& ip)
	{
		auto it = entries.find(ip);
		return it != entries.end() ? &it->second : nullptr;
	}

	const ReputationEntry* FindEntry(const std::string& ip) const
	{
		auto it = entries.find(ip);
		return it != entries.end() ? &it->second : nullptr;
	}

	ReputationEntry& GetOrCreateEntry(const std::string& ip)
	{
		auto [it, inserted] = entries.insert({ ip, ReputationEntry() });
		if (inserted)
			dirty = true;
		return it->second;
	}

	void MergeEntry(const std::string& ip, const ReputationEntry& other)
	{
		auto it = entries.find(ip);
		if (it == entries.end())
		{
			entries.insert({ ip, other });
			return;
		}

		auto& entry = it->second;
		entry.score = std::max(entry.score, other.score);
		entry.last_seen = std::max(entry.last_seen, other.last_seen);
	}

	void UpdateUsersForIP(const std::string& ip, uint16_t score)
	{
		for (const auto& [_, user] : ServerInstance->Users.GetUsers())
		{
			if (!user)
				continue;

			if (GetReputationKey(user) == ip)
				repouserext.Set(user, score, false);
		}
	}

	void UpdateUser(User* user)
	{
		const std::string ip = GetReputationKey(user);
		const auto* entry = FindEntry(ip);
		repouserext.Set(user, entry ? entry->score : 0, false);
	}

	bool IsExpired(const ReputationEntry& entry) const
	{
		const time_t now = ServerInstance->Time();
		for (const auto& rule : rules)
		{
			if (!rule.age)
				continue;

			if (now - entry.last_seen <= static_cast<time_t>(rule.age))
				continue;

			if (rule.score == -1 || entry.score <= static_cast<uint16_t>(rule.score))
				return true;
		}
		return false;
	}

	void BumpScores()
	{
		markerepoch += 2;
		const uint32_t marker_unreg = markerepoch;
		const uint32_t marker_reg = markerepoch + 1;
		const time_t now = ServerInstance->Time();

		for (auto* user : ServerInstance->Users.GetLocalUsers())
		{
			if (!user || user->quitting)
				continue;

			const std::string ip = GetReputationKey(user);
			if (ip.empty())
				continue;

			if (minchanmembers)
			{
				if (GetHighestChannelMemberCount(user) < minchanmembers)
					continue;
			}

			auto& entry = GetOrCreateEntry(ip);
			const bool loggedin = accountapi && accountapi->GetAccountName(user);

			bool scorechanged = false;
			if (entry.marker != marker_unreg && entry.marker != marker_reg)
			{
				entry.marker = marker_unreg;
				if (entry.score < scorecap)
				{
					entry.score++;
					scorechanged = true;
					if (loggedin && entry.score < scorecap)
					{
						entry.score++;
						scorechanged = true;
						entry.marker = marker_reg;
					}
					MarkUpsert(ip);
				}
			}
			else if (entry.marker == marker_unreg && loggedin && entry.score < scorecap)
			{
				entry.score++;
				scorechanged = true;
				entry.marker = marker_reg;
				MarkUpsert(ip);
			}

			const time_t oldlast = entry.last_seen;
			entry.last_seen = now;
			if (entry.last_seen != oldlast)
				MarkUpsert(ip);
			repouserext.Set(user, entry.score, false);

			// Keep remote servers in sync so opers/extbans see the same reputation.
			if (scorechanged)
				BroadcastScore(ip, ConvToStr(entry.score), ServerInstance->FakeClient);
		}
	}

	void ExpireOldEntries()
	{
		if (entries.empty())
			return;

		for (auto it = entries.begin(); it != entries.end();)
		{
			if (IsExpired(it->second))
			{
				MarkDelete(it->first);
				it = entries.erase(it);
			}
			else
			{
				++it;
			}
		}
	}

	bool LoadFlatfileDatabase()
	{
		std::error_code ec;
		if (!std::filesystem::is_regular_file(dbpath, ec))
			return true;

		std::ifstream stream(dbpath);
		if (!stream.is_open())
		{
			ServerInstance->Logs.Critical("m_reputation", "Cannot read database '{}'! {} ({})", dbpath, strerror(errno), errno);
			return false;
		}

		std::string line;
		if (!std::getline(stream, line))
			return true;

		irc::spacesepstream header(line);
		std::string magic;
		header.GetToken(magic);
		if (magic == "REPDB")
		{
			std::string dbversion;
			std::string start;
			std::string written;
			header.GetToken(dbversion);
			header.GetToken(start);
			header.GetToken(written);
			if (dbversion != "1")
				throw ModuleException(this, "Unsupported reputation database version");

			if (!start.empty())
				starttime = ConvToNum<time_t>(start);
			if (!written.empty())
				writtentime = ConvToNum<time_t>(written);
		}
		else
		{
			ServerInstance->Logs.Warning("m_reputation", "Ignoring reputation database '{}' due to unknown header.", dbpath);
			return true;
		}

		while (std::getline(stream, line))
		{
			irc::spacesepstream tokens(line);
			std::string ip;
			std::string score;
			std::string lastseen;
			tokens.GetToken(ip);
			tokens.GetToken(score);
			tokens.GetToken(lastseen);
			if (ip.empty() || score.empty() || lastseen.empty())
				continue;

			// Migrate legacy per-IP entries to the currently configured key format.
			const std::string key = NormaliseReputationKey(ip);
			if (key.empty())
				continue;

			ReputationEntry entry;
			entry.score = std::min<uint16_t>(static_cast<uint16_t>(ConvToNum<unsigned long>(score)), scorecap);
			entry.last_seen = ConvToNum<time_t>(lastseen);
			MergeEntry(key, entry);
		}

		return true;
	}

	bool SaveFlatfileDatabase()
	{
		const auto tmpdbpath = INSP_FORMAT("{}.new.{}", dbpath, ServerInstance->Time());
		std::ofstream stream(tmpdbpath);
		if (!stream.is_open())
		{
			ServerInstance->Logs.Critical("m_reputation", "Cannot create database '{}'! {} ({})", tmpdbpath, strerror(errno), errno);
			return false;
		}

		const time_t now = ServerInstance->Time();
		stream << "REPDB 1 " << starttime << ' ' << now << std::endl;
		for (const auto& [ip, entry] : entries)
		{
			if (!entry.score)
				continue;
			stream << ip << ' ' << entry.score << ' ' << entry.last_seen << std::endl;
		}

		if (stream.fail())
		{
			ServerInstance->Logs.Critical("m_reputation", "Cannot write database '{}'! {} ({})", tmpdbpath, strerror(errno), errno);
			return false;
		}
		stream.close();

#ifdef _WIN32
		std::remove(dbpath.c_str());
#endif
		if (::rename(tmpdbpath.c_str(), dbpath.c_str()) < 0)
		{
			ServerInstance->Logs.Critical("m_reputation", "Cannot replace old database '{}' with new database '{}'! {} ({})", dbpath, tmpdbpath, strerror(errno), errno);
			return false;
		}

		writtentime = now;
		return true;
	}

	bool SaveDatabase()
	{
		if (!dirty)
			return true;

		const bool ok = SaveFlatfileDatabase();
		if (ok)
			dirty = false;
		return ok;
	}

	void BroadcastScore(const std::string& ip, const std::string& scoretext, const User* source)
	{
		if (!ServerInstance->PI)
			return;

		CommandBase::Params params;
		params.push_back(ip);
		params.push_back(scoretext);
		ServerInstance->PI->BroadcastEncap("REPUTATION", params, source, nullptr);
	}

	void HandleRemoteUpdate(const std::string& ip, const std::string& scoretext)
	{
		const std::string key = NormaliseReputationKey(ip);
		if (key.empty())
			return;

		bool forced = false;
		std::string text = scoretext;
		if (!text.empty() && text.front() == '*')
		{
			// *123 or *123*
			text.erase(text.begin());
			if (!text.empty() && text.back() == '*')
			{
				forced = true;
				text.pop_back();
			}
		}

		const unsigned long ulscore = ConvToNum<unsigned long>(text, 0);
		const uint16_t score = std::min<uint16_t>(static_cast<uint16_t>(ulscore), scorecap);
		if (!score && !forced)
			return;

		auto& entry = GetOrCreateEntry(key);
		if (forced || score > entry.score)
		{
			entry.score = score;
			entry.last_seen = ServerInstance->Time();
			MarkUpsert(key);
			UpdateUsersForIP(key, score);
		}
	}

	void ShowStats(User* user)
	{
		const time_t now = ServerInstance->Time();
		user->WriteNotice("Reputation module statistics:");
		user->WriteNotice(INSP_FORMAT("Recording for: {} (since unixtime {})", Duration::ToLongString(static_cast<unsigned long>(now - starttime)), starttime));
		if (writtentime)
			user->WriteNotice(INSP_FORMAT("Last successful db write: {} ago (unixtime {})", Duration::ToLongString(static_cast<unsigned long>(now - writtentime)), writtentime));
		else
			user->WriteNotice("Last successful db write: never");
		user->WriteNotice("Persistence: flatfile=yes");
		user->WriteNotice(INSP_FORMAT("Current number of records (IP's): {}", entries.size()));
		user->WriteNotice("-");
		user->WriteNotice("Available commands:");
		user->WriteNotice("/REPUTATION <nick>          Show reputation info about nick");
		user->WriteNotice("/REPUTATION <nick> <value>  Set reputation score of nick IP");
		user->WriteNotice("/REPUTATION <ip>            Show reputation info about IP");
		user->WriteNotice("/REPUTATION <ip> <value>    Set reputation score of IP");
		user->WriteNotice("/REPUTATION <channel>       List users in channel along with their reputation score");
		user->WriteNotice("/REPUTATION <NN             List users with reputation score below NN");
		user->WriteNotice("/REPUTATION >NN             List users with reputation score above NN");
	}

	void ShowRecord(User* user, const std::string& ip)
	{
		const std::string key = NormaliseReputationKey(ip);
		if (key.empty())
		{
			user->WriteNotice(INSP_FORMAT("Invalid IP address '{}'", ip));
			return;
		}

		auto* entry = FindEntry(key);
		if (!entry)
		{
			user->WriteNotice(INSP_FORMAT("No reputation record found for {}", key));
			return;
		}

		const time_t now = ServerInstance->Time();
		user->WriteNotice("****************************************************");
		user->WriteNotice(INSP_FORMAT("Reputation record for {}:", key));
		user->WriteNotice(INSP_FORMAT("    Score: {}", entry->score));
		user->WriteNotice(INSP_FORMAT("Last seen: {} ago (unixtime: {})", Duration::ToLongString(static_cast<unsigned long>(now - entry->last_seen)), entry->last_seen));
		user->WriteNotice("****************************************************");
	}

	void SetScore(User* user, const std::string& ip, unsigned long value)
	{
		const std::string key = NormaliseReputationKey(ip);
		if (key.empty())
		{
			user->WriteNotice(INSP_FORMAT("Invalid IP address '{}'", ip));
			return;
		}

		const uint16_t score = std::min<uint16_t>(static_cast<uint16_t>(value), scorecap);
		auto& entry = GetOrCreateEntry(key);
		entry.score = score;
		entry.last_seen = ServerInstance->Time();
		MarkUpsert(key);
		UpdateUsersForIP(key, score);

		BroadcastScore(key, INSP_FORMAT("*{}*", score), ServerInstance->FakeClient);
		user->WriteNotice(INSP_FORMAT("Reputation of {} set to {}", key, score));
	}

	void ChannelQuery(User* user, Channel* channel)
	{
		std::vector<std::pair<uint16_t, User*>> list;
		list.reserve(channel->GetUsers().size());

		for (const auto& [chanuser, _] : channel->GetUsers())
		{
			const auto score = static_cast<uint16_t>(std::max<intptr_t>(0, repouserext.Get(chanuser)));
			list.push_back({ score, chanuser });
		}

		std::sort(list.begin(), list.end(), [](const auto& a, const auto& b) {
			if (a.first != b.first)
				return a.first > b.first;
			return irc::insensitive_swo()(a.second->nick, b.second->nick);
		});

		user->WriteNotice(INSP_FORMAT("Users and reputation scores for {}:", channel->name));
		std::string buf;
		for (size_t i = 0; i < list.size(); ++i)
		{
			const auto& [score, u] = list[i];
			const std::string token = INSP_FORMAT("{}({}) ", u->nick, score);
			if (buf.size() + token.size() > 380)
			{
				user->WriteNotice(buf);
				buf.clear();
			}
			buf.append(token);
		}
		if (!buf.empty())
			user->WriteNotice(buf);
		user->WriteNotice("End of list.");
	}

	void ListQuery(User* user, unsigned long maxscore)
	{
		user->WriteNotice(INSP_FORMAT("Users and reputation scores <{}:", maxscore));
		for (const auto& [_, target] : ServerInstance->Users.GetUsers())
		{
			if (!target || IS_SERVER(target) || target->server->IsService())
				continue;

			const auto score = static_cast<unsigned long>(std::max<intptr_t>(0, repouserext.Get(target)));
			if (score >= maxscore)
				continue;

			user->WriteNotice(INSP_FORMAT("{}!{}@{} [{}] (score: {})",
				target->nick,
				target->GetUser(false),
				target->GetRealHost(),
				target->GetAddress(),
				score));
		}
		user->WriteNotice("End of list.");
	}

	void ListQueryAbove(User* user, unsigned long minscore)
	{
		user->WriteNotice(INSP_FORMAT("Users and reputation scores >{}:", minscore));
		for (const auto& [_, target] : ServerInstance->Users.GetUsers())
		{
			if (!target || IS_SERVER(target) || target->server->IsService())
				continue;

			const auto score = static_cast<unsigned long>(std::max<intptr_t>(0, repouserext.Get(target)));
			if (score <= minscore)
				continue;

			user->WriteNotice(INSP_FORMAT("{}!{}@{} [{}] (score: {})",
				target->nick,
				target->GetUser(false),
				target->GetRealHost(),
				target->GetAddress(),
				score));
		}
		user->WriteNotice("End of list.");
	}

public:
	ModuleReputation()
		: Module(VF_VENDOR, "Provides a scoring system for known IPs.")
		, Whois::EventListener(this)
		, accountapi(this)
		, repouserext(this, "reputation", ExtensionType::USER)
		, scoreextban(this, repouserext)
		, cmd(this, *this)
		, bumptimer(*this, ReputationTimer::Type::BUMP, 0)
		, expiretimer(*this, ReputationTimer::Type::EXPIRE, 0)
		, savetimer(*this, ReputationTimer::Type::SAVE, 0)
	{
	}

	~ModuleReputation() override
	{
		SaveDatabase();
	}

	void init() override
	{
		if (!starttime)
			starttime = ServerInstance->Time();

		// On module reload, init() may run before ReadConfig(). Ensure we have a
		// usable database path before attempting to load.
		if (dbpath.empty())
		{
			const auto& tag = ServerInstance->Config->ConfValue("reputation");
			dbpath = ServerInstance->Config->Paths.PrependData(tag->getString("database", "reputation.db", 1));
		}

		LoadFlatfileDatabase();

		// On module load/reload we might already have local users. Ensure their
		// current reputation is synced to the network.
		for (auto* user : ServerInstance->Users.GetLocalUsers())
		{
			if (!user || user->quitting)
				continue;
			UpdateUser(user);

			const std::string ip = GetReputationKey(user);
			if (ip.empty())
				continue;

			const auto score = static_cast<unsigned long>(std::max<intptr_t>(0, repouserext.Get(user)));
			if (score)
				BroadcastScore(ip, ConvToStr(score), ServerInstance->FakeClient);
		}

		// Add timers.
		bumptimer.SetInterval(bumpinterval);
		expiretimer.SetInterval(expireinterval);
		savetimer.SetInterval(saveinterval);

		if (!bumptimer.GetTrigger())
			ServerInstance->Timers.AddTimer(&bumptimer);
		if (!expiretimer.GetTrigger())
			ServerInstance->Timers.AddTimer(&expiretimer);
		if (!savetimer.GetTrigger())
			ServerInstance->Timers.AddTimer(&savetimer);
	}

	void ReadConfig(ConfigStatus& status) override
	{
		const auto& tag = ServerInstance->Config->ConfValue("reputation");
		if (dbpath.empty())
			dbpath = ServerInstance->Config->Paths.PrependData(tag->getString("database", "reputation.db", 1));

		ipv4prefix = static_cast<unsigned char>(tag->getNum<unsigned short>("ipv4prefix", 32, 0, 32));
		ipv6prefix = static_cast<unsigned char>(tag->getNum<unsigned short>("ipv6prefix", 64, 0, 128));
		if (ipv6prefix == 0)
			ipv6prefix = 128;
		if (ipv4prefix == 0)
			ipv4prefix = 32;

		bumpinterval = tag->getDuration("bumpinterval", DEFAULT_BUMP_INTERVAL, 1);
		expireinterval = tag->getDuration("expireinterval", DEFAULT_EXPIRE_INTERVAL, 1);
		saveinterval = tag->getDuration("saveinterval", DEFAULT_SAVE_INTERVAL, 1);
		minchanmembers = tag->getNum<unsigned long>("minchanmembers", 3);
		scorecap = tag->getNum<uint16_t>("scorecap", DEFAULT_SCORE_CAP, 1, DEFAULT_SCORE_CAP);

		const std::string whois = tag->getString("whois", "all");
		if (irc::equals(whois, "none"))
			whoisvis = WhoisVisibility::NONE;
		else if (irc::equals(whois, "self"))
			whoisvis = WhoisVisibility::SELF;
		else if (irc::equals(whois, "all"))
			whoisvis = WhoisVisibility::ALL;
		else
			whoisvis = WhoisVisibility::OPERS;

		rules.clear();
		for (const auto& [_, exptag] : ServerInstance->Config->ConfTags("reputationexpire"))
		{
			ExpireRule rule;
			rule.score = exptag->getNum<int>("score", -1);
			rule.age = exptag->getDuration("age", 0);
			if (rule.age)
				rules.push_back(rule);
		}

		if (rules.empty())
		{
			// Match Unreal defaults.
			rules.push_back({ 2, 3600 });
			rules.push_back({ 6, 86400 * 7UL });
			rules.push_back({ 12, 86400 * 30UL });
			rules.push_back({ -1, 86400 * 90UL });
		}

		// If already running then update timer intervals.
		if (bumptimer.GetTrigger())
			bumptimer.SetInterval(bumpinterval);
		if (expiretimer.GetTrigger())
			expiretimer.SetInterval(expireinterval);
		if (savetimer.GetTrigger())
			savetimer.SetInterval(saveinterval);
	}

	void OnWhois(Whois::Context& whois) override
	{
		if (whoisvis == WhoisVisibility::NONE)
			return;

		User* source = whois.GetSource();
		User* target = whois.GetTarget();

		if (whoisvis == WhoisVisibility::SELF && source != target)
			return;
		if (whoisvis == WhoisVisibility::OPERS && source != target && !source->HasPrivPermission("users/auspex"))
			return;

		const auto score = std::max<intptr_t>(0, repouserext.Get(target));
		if (score > 0)
			whois.SendLine(RPL_WHOISSPECIAL, INSP_FORMAT("is using an IP with a reputation score of {}", score));
	}

	void OnUserPostInit(LocalUser* user) override
	{
		UpdateUser(user);

		const std::string ip = GetReputationKey(user);
		const auto score = static_cast<uint16_t>(std::max<intptr_t>(0, repouserext.Get(user)));
		if (!ip.empty() && score)
			BroadcastScore(ip, ConvToStr(score), ServerInstance->FakeClient);
	}

	void OnChangeRemoteAddress(LocalUser* user) override
	{
		UpdateUser(user);
	}
};
CommandReputation::CommandReputation(Module* Creator, ModuleReputation& Parent)
	: Command(Creator, "REPUTATION", 0, 2)
	, parent(Parent)
{
	// Must be callable via ENCAP by remote servers (which won't have oper access
	// in the command parser). We enforce oper-only access for local users in
	// Handle() instead.
	access_needed = CmdAccess::NORMAL;
	syntax = { "[<nick|ip|#channel|<N|>N>] [<value>]" };
}

RouteDescriptor CommandReputation::GetRouting(User* user, const Params& parameters)
{
	return ROUTE_LOCALONLY;
}

CmdResult CommandReputation::Handle(User* user, const Params& parameters)
{
	// Remote update: ENCAP * REPUTATION <ip> <score>
	if (!IS_LOCAL(user) && parameters.size() >= 2 && LooksLikeIP(parameters[0]))
	{
		parent.HandleRemoteUpdate(parameters[0], parameters[1]);
		return CmdResult::SUCCESS;
	}

	LocalUser* localuser = IS_LOCAL(user);
	if (!localuser)
		return CmdResult::SUCCESS;

	if (!localuser->IsOper())
	{
		localuser->WriteNumeric(ERR_NOPRIVILEGES, "Permission Denied - You do not have the required operator privileges");
		return CmdResult::FAILURE;
	}

	if (parameters.empty())
	{
		parent.ShowStats(localuser);
		return CmdResult::SUCCESS;
	}

	const std::string& target = parameters[0];

	if (!target.empty() && target[0] == '#')
	{
		Channel* chan = ServerInstance->Channels.Find(target);
		if (!chan)
		{
			localuser->WriteNumeric(Numerics::NoSuchChannel(target));
			return CmdResult::FAILURE;
		}

		parent.ChannelQuery(localuser, chan);
		return CmdResult::SUCCESS;
	}

	if (!target.empty() && target[0] == '<')
	{
		unsigned long max = ConvToNum<unsigned long>(target.substr(1));
		if (max < 1)
		{
			localuser->WriteNotice("REPUTATION: Invalid search value. Use e.g. /REPUTATION <5");
			return CmdResult::FAILURE;
		}
		parent.ListQuery(localuser, max);
		return CmdResult::SUCCESS;
	}

	if (!target.empty() && target[0] == '>')
	{
		unsigned long min = ConvToNum<unsigned long>(target.substr(1));
		if (min < 1)
		{
			localuser->WriteNotice("REPUTATION: Invalid search value. Use e.g. /REPUTATION >1");
			return CmdResult::FAILURE;
		}
		parent.ListQueryAbove(localuser, min);
		return CmdResult::SUCCESS;
	}

	std::string ip;
	if (LooksLikeIP(target))
	{
		ip = target;
	}
	else
	{
		User* u = ServerInstance->Users.FindNick(target);
		if (!u)
		{
			localuser->WriteNumeric(Numerics::NoSuchNick(target));
			return CmdResult::FAILURE;
		}
		ip = u->GetAddress();
		if (ip.empty())
		{
			localuser->WriteNotice(INSP_FORMAT("No IP address information available for user {}.", target));
			return CmdResult::FAILURE;
		}
	}

	if (parameters.size() > 1)
	{
		unsigned long value = ConvToNum<unsigned long>(parameters[1]);
		parent.SetScore(localuser, ip, value);
		return CmdResult::SUCCESS;
	}

	parent.ShowRecord(localuser, ip);
	return CmdResult::SUCCESS;
}

bool ReputationTimer::Tick()
{
	switch (type)
	{
		case Type::BUMP:
			parent.BumpScores();
			break;
		case Type::EXPIRE:
			parent.ExpireOldEntries();
			break;
		case Type::SAVE:
			parent.SaveDatabase();
			break;
	}
	return true;
}

MODULE_INIT(ModuleReputation)
