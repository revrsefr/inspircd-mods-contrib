/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   Copyright (C) 2024 Jean Chevronnet <mike.chevronnet@gmail.com>
 *
 * This file contains a third party module for InspIRCd.  You can
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
#include "modules/ssl.h"
#include "modules/whois.h"
#include "modules/server.h"
#include "extension.h"

class SNIExtension final
	: public ExtensionItem
{
public:
	SNIExtension(Module* parent)
		: ExtensionItem(parent, "sni_hostname", ExtensionType::USER)
	{
	}

	std::string* Get(const User* user) const
	{
		return static_cast<std::string*>(GetRaw(user));
	}

	void Set(User* user, std::string* value, bool sync = true)
	{
		std::string* old = static_cast<std::string*>(SetRaw(user, value));
		if (old)
			delete old;

		if (sync)
			Sync(user, value);
	}

	std::string ToInternal(const Extensible* container, void* item) const noexcept override
	{
		return ToNetwork(container, item);
	}

	std::string ToNetwork(const Extensible* container, void* item) const noexcept override
	{
		std::string* hostname = static_cast<std::string*>(item);
		return *hostname;
	}

	void FromInternal(Extensible* container, const std::string& value) noexcept override
	{
		FromNetwork(container, value);
	}

	void FromNetwork(Extensible* container, const std::string& value) noexcept override
	{
		if (container->extype != this->extype)
			return;

		auto* hostname = new std::string(value);
		Set(static_cast<User*>(container), hostname, false);
	}

	void Delete(Extensible* container, void* item) override
	{
		std::string* hostname = static_cast<std::string*>(item);
		if (hostname)
			delete hostname;
	}
};

class ModuleIRCv3SNI final
	: public Module
	, public ServerProtocol::LinkEventListener
	, public Whois::EventListener
{
private:
	SNIExtension sniext;
	bool announcesni;
	char snomask;

public:
	ModuleIRCv3SNI()
		: Module(VF_VENDOR | VF_OPTCOMMON, "Adds support for TLS Server Name Indication (SNI) which allows servers to present different certificates based on the hostname the client is connecting to.")
		, ServerProtocol::LinkEventListener(this)
		, Whois::EventListener(this)
		, sniext(this)
		, announcesni(false)
		, snomask('a')
	{
	}

	void ReadConfig(ConfigStatus& status) override
	{
		const auto& tag = ServerInstance->Config->ConfValue("sni");
		announcesni = tag->getBool("announcesni", false);
		std::string mask = tag->getString("snomask", "a");
		
		if (!mask.empty())
			snomask = mask[0];
		
		if (snomask < 'a' || snomask > 'z')
			snomask = 'a';
	}

	void OnPostConnect(User* user) override
	{
		// We only want to handle local users
		LocalUser* localuser = IS_LOCAL(user);
		if (!localuser)
			return;

		SSLIOHook* sslhook = SSLIOHook::IsSSL(&localuser->eh);
		if (!sslhook)
			return;
			
		std::string hostname;
		if (sslhook->GetServerName(hostname) && !hostname.empty())
		{
			auto* stored_hostname = new std::string(hostname);
			sniext.Set(user, stored_hostname);
			
			if (announcesni)
			{
				ServerInstance->SNO.WriteToSnoMask(snomask, "Client {} is using SNI with hostname: {}",
					user->GetMask(), hostname);
			}
			
			ServerInstance->Logs.Debug(MODNAME, "Client {} is using SNI with hostname: {}",
				user->GetMask(), hostname);
		}
	}

	void OnWhois(Whois::Context& whois) override
	{
		User* source = whois.GetSource();
		User* target = whois.GetTarget();

		// Only show SNI information if the requesting user has the appropriate privileges
		if (!source->HasPrivPermission("users/auspex"))
			return;

		std::string* sni_hostname = sniext.Get(target);
		if (sni_hostname)
		{
			// Send the SNI hostname information in the WHOIS response
			whois.SendLine(RPL_WHOISSPECIAL,"*", "is using SNI with hostname " + *sni_hostname);
		}
	}
};

MODULE_INIT(ModuleIRCv3SNI)
