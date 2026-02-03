/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   Copyright (C) 2025 Jean Chevronnet <revrsedev@gmail.com>
 *
 * This file is part of InspIRCd.  InspIRCd is free software: you can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License as published by the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/// $ModAuthor: reverse
/// $ModAuthorMail: revrsedev@email.com
/// $ModDepends: core 4
/// $ModDesc: Warns IRC operators and Z-lines botnets trying to use WebSockets.
/// $ModConfig: <detectfakewebsocket origin="example.com,chat.example.net" requireorigin="yes" require_realip="no" require_realhost="no" zline_duration="3600" zline_reason="Botnet detected using WebSockets!">

#include "inspircd.h"
#include "xline.h"
#include "extension.h"
#include "iohook.h"
#include <algorithm>
#include <cctype>

class ModuleDetectFakeWebSocket final : public Module
{
private:
    std::vector<std::string> allowed_origins;
    int zline_duration;
    std::string zline_reason;
    bool require_origin;
    bool require_realip;
    bool require_realhost;

    // Reference to the existing WebSocket Origin extension from m_websocket.cpp
    StringExtItem* websocket_origin;
    StringExtItem* websocket_realhost;
    StringExtItem* websocket_realip;

    static bool HasExt(const Extensible* ext, const std::string& extname)
    {
        ExtensionItem* item = ServerInstance->Extensions.GetItem(extname);
        if (!item)
            return false;

        const auto& extlist = ext->GetExtList();
        return extlist.find(item) != extlist.end();
    }

    static bool IsWebSocketUser(LocalUser* user)
    {
        // Prefer checking the websocket module's extension items as this is
        // stable even when hook ordering differs.
        if (HasExt(user, "websocket-origin") || HasExt(user, "websocket-realhost") || HasExt(user, "websocket-realip"))
            return true;

        // Fallback: check if the user's socket has a websocket I/O hook.
        for (IOHook* hook = user->eh.GetIOHook(); hook; )
        {
            if (hook->prov && insp::equalsci(hook->prov->name, "websocket"))
                return true;

            IOHookMiddle* middle = IOHookMiddle::ToMiddleHook(hook);
            hook = middle ? middle->GetNextHook() : nullptr;
        }
        return false;
    }

    static std::string Trim(const std::string& value)
    {
        const auto start = value.find_first_not_of(" \t\r\n");
        if (start == std::string::npos)
            return "";
        const auto end = value.find_last_not_of(" \t\r\n");
        return value.substr(start, end - start + 1);
    }

    static std::string ExtractOriginHost(const std::string& origin)
    {
        std::string host = Trim(origin);
        const auto scheme = host.find("://");
        if (scheme != std::string::npos)
            host.erase(0, scheme + 3);
        if (host.rfind("//", 0) == 0)
            host.erase(0, 2);

        const auto path = host.find('/');
        if (path != std::string::npos)
            host.erase(path);

        const auto port = host.find(':');
        if (port != std::string::npos)
            host.erase(port);

        std::transform(host.begin(), host.end(), host.begin(), [](unsigned char chr) { return static_cast<char>(std::tolower(chr)); });
        return host;
    }

    static bool SuffixMatch(const std::string& value, const std::string& suffix)
    {
        if (value == suffix)
            return true;
        if (value.length() <= suffix.length())
            return false;
        if (value.compare(value.length() - suffix.length(), suffix.length(), suffix) != 0)
            return false;
        return value[value.length() - suffix.length() - 1] == '.';
    }

    // Check if the WebSocket origin is allowed
    bool IsAllowedOrigin(const std::string& origin)
    {
        if (allowed_origins.empty())
            return true;

        const std::string host = ExtractOriginHost(origin);
        if (host.empty())
            return false;

        for (const auto& allowed_origin : allowed_origins)
        {
            if (SuffixMatch(host, allowed_origin))
                return true;
        }
        return false;
    }

    // Extract the actual WebSocket Origin from m_websocket.cpp
    std::string GetUserWebSocketOrigin(LocalUser* user) const
    {
        if (!websocket_origin)
            return "";

        const std::string* origin = websocket_origin->Get(user);
        return origin ? *origin : "";
    }

    static std::string GetExtValue(StringExtItem* item, LocalUser* user)
    {
        if (!item)
            return "";
        const std::string* value = item->Get(user);
        return value ? *value : "";
    }

public:
    ModuleDetectFakeWebSocket()
        : Module(VF_VENDOR, "Detects and Z-lines botnets faking WebSocket connections."),
          websocket_origin(nullptr),
          websocket_realhost(nullptr),
          websocket_realip(nullptr)
    {
    }

    void ReadConfig(ConfigStatus& status) override
    {
        const auto& tag = ServerInstance->Config->ConfValue("detectfakewebsocket");

        zline_duration = tag->getNum<int>("zline_duration", 3600);
        zline_reason = tag->getString("zline_reason", "Botnet detected using WebSockets!");
        require_origin = tag->getBool("requireorigin", true);
        require_realip = tag->getBool("require_realip", false);
        require_realhost = tag->getBool("require_realhost", false);

        // Read and split multiple allowed origins
        std::string origins = tag->getString("origin", "");
        allowed_origins.clear();
        irc::commasepstream originstream(origins);
        std::string origin;
        while (originstream.GetToken(origin))
        {
            const std::string host = ExtractOriginHost(origin);
            if (!host.empty())
                allowed_origins.push_back(host);
        }

        // Get the existing WebSocket extensions from m_websocket.cpp
        websocket_origin = static_cast<StringExtItem*>(ServerInstance->Extensions.GetItem("websocket-origin"));
        websocket_realhost = static_cast<StringExtItem*>(ServerInstance->Extensions.GetItem("websocket-realhost"));
        websocket_realip = static_cast<StringExtItem*>(ServerInstance->Extensions.GetItem("websocket-realip"));

        ServerInstance->Logs.Normal("m_detect_fake_websocket",
            "Loaded config: requireorigin=%s, require_realip=%s, require_realhost=%s, allowed_origins=%s, zline=%d",
            require_origin ? "yes" : "no",
            require_realip ? "yes" : "no",
            require_realhost ? "yes" : "no",
            origins.c_str(), zline_duration);
    }

    void Prioritize() override
    {
        ServerInstance->Modules.SetPriority(this, I_OnUserRegister, PRIORITY_FIRST);
    }

    ModResult OnUserRegister(LocalUser* user) override
    {
        if (!IsWebSocketUser(user))
            return MOD_RES_PASSTHRU;

        const std::string real_origin = GetUserWebSocketOrigin(user);
        const bool has_origin = !real_origin.empty();
        const bool origin_allowed = has_origin && IsAllowedOrigin(real_origin);
        const std::string realip = GetExtValue(websocket_realip, user);
        const std::string realhost = GetExtValue(websocket_realhost, user);

        std::vector<std::string> problems;
        if (require_origin && !has_origin)
            problems.push_back("missing origin");
        if (has_origin && !origin_allowed)
            problems.push_back("origin not allowed");
        if (require_realip && realip.empty())
            problems.push_back("missing real ip");
        if (require_realhost && realhost.empty())
            problems.push_back("missing real host");

        if (problems.empty())
            return MOD_RES_PASSTHRU;

        std::string reason;
        for (size_t i = 0; i < problems.size(); ++i)
        {
            if (i)
                reason.append(", ");
            reason.append(problems[i]);
        }

        const std::string client_ip = user->GetAddress();
        ServerInstance->Logs.Normal("m_detect_fake_websocket",
            "Botnet detected! %s via WebSocket (origin=%s, realip=%s, realhost=%s) [%s]. Applying Z-line...",
            client_ip.c_str(),
            has_origin ? real_origin.c_str() : "(missing)",
            realip.empty() ? "(missing)" : realip.c_str(),
            realhost.empty() ? "(missing)" : realhost.c_str(),
            reason.c_str());

        for (LocalUser* u : ServerInstance->Users.GetLocalUsers())
        {
            if (u->IsOper())
            {
                u->WriteNotice(INSP_FORMAT(
                    "WARNING: Botnet detected! {} via WebSocket (origin={}, realip={}, realhost={}) [{}]. Applying Z-line.",
                    client_ip,
                    has_origin ? real_origin : "(missing)",
                    realip.empty() ? "(missing)" : realip,
                    realhost.empty() ? "(missing)" : realhost,
                    reason));
            }
        }

        // Apply a Z-line ban
        ZLine* zl = new ZLine(ServerInstance->Time(), zline_duration, "FakeWebSocket", zline_reason, client_ip);
        if (ServerInstance->XLines->AddLine(zl, nullptr))
        {
            ServerInstance->XLines->ApplyLines();
        }

        // Disconnect the user immediately
        ServerInstance->Users.QuitUser(user, zline_reason);

        return MOD_RES_PASSTHRU;
    }
};

MODULE_INIT(ModuleDetectFakeWebSocket)
