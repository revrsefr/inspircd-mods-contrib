/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   Copyright (C) 2025 revrsefr 
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

/// $ModAuthor: reverse mike.chevronnet@gmail.com
/// $ModDesc: Provides support for KiwiIRC-specific tags
/// $ModDepends: core 4
/// $ModConfig: <kiwiirctags enablefileupload="yes" enableconference="yes" enabletictactoe="yes" logusage="no" maxuploadsize="10M" restrictconferenceto="oper" notifychannelops="yes" notificationformat="%source% is using %tagtype% in %channel%">

#include "inspircd.h"
#include "extension.h"          // For ExtensionType::USER
#include "modules/cap.h"         // For Cap::Capability
#include "modules/ctctags.h"
#include "modules/stats.h"
#include "timeutils.h"

// Feature tracking extension item
class TagUsageExtItem : public ExtensionItem
{
public:
    struct TagStats
    {
        unsigned long fileupload_count = 0;
        unsigned long conference_count = 0;
        unsigned long tictactoe_count = 0;
        time_t first_seen = 0;
        time_t last_seen = 0;
    };

    TagUsageExtItem(Module* mod) 
        : ExtensionItem(mod, "kiwiirc_tag_usage", ExtensionType::USER) 
    {
    }

    void FromNetwork(Extensible* container, const std::string& value) noexcept override
    {
        // Not network serializable
    }

    std::string ToNetwork(const Extensible* container, void* item) const noexcept override
    {
        // Not network serializable
        return "";
    }

    TagStats* Get(User* user)
    {
        TagStats* stats = static_cast<TagStats*>(GetRaw(user));
        if (!stats)
        {
            stats = new TagStats;
            stats->first_seen = ServerInstance->Time();
            SetRaw(user, stats);
        }
        return stats;
    }

    void UpdateStats(User* user, const std::string& tagname)
    {
        TagStats* stats = Get(user);
        stats->last_seen = ServerInstance->Time();

        if (tagname == "+kiwiirc.com/fileuploader")
            stats->fileupload_count++;
        else if (tagname == "+kiwiirc.com/conference")
            stats->conference_count++;
        else if (tagname == "+data" || tagname == "+kiwiirc.com/ttt")
            stats->tictactoe_count++;
    }

    std::string FormatStats(TagStats* stats) const
    {
        std::string result = "First seen: " + 
                            Time::ToString(stats->first_seen) +
                            ", Last seen: " +
                            Time::ToString(stats->last_seen) +
                            ", Usage counts: Uploads: " +
                            ConvToStr(stats->fileupload_count) +
                            ", Conferences: " +
                            ConvToStr(stats->conference_count) +
                            ", Games: " +
                            ConvToStr(stats->tictactoe_count);
        return result;
    }

    void Delete(Extensible* container, void* item) override
    {
        delete static_cast<TagStats*>(item);
    }
};

class KiwiIRCTagProvider final
    : public ClientProtocol::MessageTagProvider
{
private:
    std::string tagname;
    Cap::Capability messagetags;
    bool enabled;
    std::string restriction;
    TagUsageExtItem& stats_ext;
    
public:
    KiwiIRCTagProvider(Module* mod, const std::string& tag, bool enabled_by_default, const std::string& restrict_to, TagUsageExtItem& stats)
        : ClientProtocol::MessageTagProvider(mod)
        , tagname(tag)
        , messagetags(mod, "message-tags")
        , enabled(enabled_by_default)
        , restriction(restrict_to)
        , stats_ext(stats)
    {
    }

    void SetEnabled(bool new_state) { enabled = new_state; }
    bool IsEnabled() const { return enabled; }
    void SetRestriction(const std::string& restrict_to) { restriction = restrict_to; }

    ModResult OnProcessTag(User* user, const std::string& name, std::string& value) override
    {
        if (name == tagname)
        {
            if (!enabled)
                return MOD_RES_DENY;
                
            // Check restrictions
            if (!restriction.empty())
            {
                if (restriction == "oper" && !user->IsOper())
                    return MOD_RES_DENY;
                    
                if (restriction == "admin" && (!user->IsOper() || !user->HasPrivPermission("admin")))
                    return MOD_RES_DENY;
            }
            
            // Track usage statistics
            stats_ext.UpdateStats(user, name);
            
            return MOD_RES_ALLOW;
        }
        
        return MOD_RES_PASSTHRU;
    }

    bool ShouldSendTag(LocalUser* user, const ClientProtocol::MessageTagData& tagdata) override
    {
        return enabled && messagetags.IsEnabled(user);
    }
};

class ModuleKiwiIRCTags final
    : public Module, public Stats::EventListener
{
private:
    const std::string file_uploader_tag = "+kiwiirc.com/fileuploader";
    const std::string conference_tag = "+kiwiirc.com/conference";
    const std::string tictactoe_old_tag = "+data";
    const std::string tictactoe_tag = "+kiwiirc.com/ttt";

    KiwiIRCTagProvider file_uploader_provider;
    KiwiIRCTagProvider conference_provider;
    KiwiIRCTagProvider tictactoe_old_provider;
    KiwiIRCTagProvider tictactoe_provider;
    
    TagUsageExtItem tag_stats;
    
    // Configuration options
    bool log_usage;
    std::string max_upload_size;
    bool notify_channel_ops;
    std::string notification_format;

public:
    ModuleKiwiIRCTags()
        : Module(VF_VENDOR, "Provides support for KiwiIRC-specific tags")
        , Stats::EventListener(this)
        , tag_stats(this)
        , file_uploader_provider(this, file_uploader_tag, true, "", tag_stats)
        , conference_provider(this, conference_tag, true, "", tag_stats)
        , tictactoe_old_provider(this, tictactoe_old_tag, true, "", tag_stats)
        , tictactoe_provider(this, tictactoe_tag, true, "", tag_stats)
        , log_usage(false)
        , max_upload_size("10M")
        , notify_channel_ops(false)
        , notification_format("%source% is using %tagtype% in %channel%")
    {
    }

    void ReadConfig(ConfigStatus& status) override
    {
        const auto& tag = ServerInstance->Config->ConfValue("kiwiirctags");
        
        // Feature toggles
        file_uploader_provider.SetEnabled(tag->getBool("enablefileupload", true));
        conference_provider.SetEnabled(tag->getBool("enableconference", true));
        bool enable_tictactoe = tag->getBool("enabletictactoe", true);
        tictactoe_old_provider.SetEnabled(enable_tictactoe);
        tictactoe_provider.SetEnabled(enable_tictactoe);
        
        // Restrictions
        file_uploader_provider.SetRestriction(tag->getString("restrictuploadto", ""));
        conference_provider.SetRestriction(tag->getString("restrictconferenceto", ""));
        std::string ttt_restriction = tag->getString("restricttictactoeto", "");
        tictactoe_old_provider.SetRestriction(ttt_restriction);
        tictactoe_provider.SetRestriction(ttt_restriction);
        
        // Other options
        log_usage = tag->getBool("logusage", false);
        max_upload_size = tag->getString("maxuploadsize", "10M");
        notify_channel_ops = tag->getBool("notifychannelops", false);
        notification_format = tag->getString("notificationformat", 
                                            "%source% is using %tagtype% in %channel%");
    }

    // Fixed method signature for InspIRCd v4
    ModResult OnUserPreMessage(User* user, const MessageTarget& target, MessageDetails& details) override
    {
        if (!details.tags_out.empty() && notify_channel_ops && target.type == MessageTarget::TYPE_CHANNEL)
        {
            Channel* chan = target.Get<Channel>();
            
            // Detect which tag is being used
            std::string tag_type;
            if (details.tags_out.find(file_uploader_tag) != details.tags_out.end())
                tag_type = "file upload";
            else if (details.tags_out.find(conference_tag) != details.tags_out.end())
                tag_type = "conference";
            else if (details.tags_out.find(tictactoe_old_tag) != details.tags_out.end() || 
                     details.tags_out.find(tictactoe_tag) != details.tags_out.end())
                tag_type = "game";
            
            // If a KiwiIRC tag was found
            if (!tag_type.empty())
            {
                // Create notification for channel operators
                std::string notification = notification_format;
                strlreplace(notification, "%source%", user->nick);
                strlreplace(notification, "%tagtype%", tag_type);
                strlreplace(notification, "%channel%", chan->name);
                
                // Send notice to channel operators
                for (const auto& [member, _] : chan->GetPrefixUsers())
                {
                    if (member->HasMode('o') || member->HasMode('a'))
                    {
                        member->WriteNotice("*** " + notification);
                    }
                }
            }
        }
        
        // Log usage if enabled
        if (log_usage && !details.tags_out.empty())
        {
            for (const auto& [tagname, _] : details.tags_out)
            {
                if (tagname == file_uploader_tag || 
                    tagname == conference_tag || 
                    tagname == tictactoe_old_tag || 
                    tagname == tictactoe_tag)
                {
                    ServerInstance->Logs.Log("MODULE", LOG_DEFAULT, 
                                           "KiwiIRC tag '%s' used by %s", 
                                           tagname.c_str(), user->GetFullHost().c_str());
                    break;
                }
            }
        }
        
        return MOD_RES_PASSTHRU;
    }

    // Stats reporting
    bool OnStats(Stats::Context& stats) override
    {
        if (stats.GetSymbol() == 'K')
        {
            stats.AddRow(998, "KiwiIRC Tags Module:");
            stats.AddRow(998, "  File Upload: " + std::string(file_uploader_provider.IsEnabled() ? "enabled" : "disabled"));
            stats.AddRow(998, "  Conference: " + std::string(conference_provider.IsEnabled() ? "enabled" : "disabled"));
            stats.AddRow(998, "  Tic-Tac-Toe: " + std::string(tictactoe_provider.IsEnabled() ? "enabled" : "disabled"));
            stats.AddRow(998, "  Max Upload Size: " + max_upload_size);
            
            unsigned long total_users = 0;
            unsigned long total_uploads = 0;
            unsigned long total_conferences = 0;
            unsigned long total_games = 0;
            
            for (auto* user : ServerInstance->Users.GetLocalUsers())
            {
                auto* userstats = tag_stats.Get(user);
                if (userstats->fileupload_count || userstats->conference_count || userstats->tictactoe_count)
                {
                    total_users++;
                    total_uploads += userstats->fileupload_count;
                    total_conferences += userstats->conference_count;
                    total_games += userstats->tictactoe_count;
                    
                    stats.AddRow(999, user->nick + ": " + tag_stats.FormatStats(userstats));
                }
            }
            
            stats.AddRow(998, "  Total active users: " + ConvToStr(total_users));
            stats.AddRow(998, "  Total uploads: " + ConvToStr(total_uploads));
            stats.AddRow(998, "  Total conferences: " + ConvToStr(total_conferences));
            stats.AddRow(998, "  Total games: " + ConvToStr(total_games));
            
            return true;
        }
        
        return false;
    }

    void OnOperRejoin(User* user, Channel* channel) override
    {
        // Show KiwiIRC usage summary to oper when they op-rejoin a channel
        if (notify_channel_ops)
        {
            std::string usage_summary;
            int user_count = 0;
            
            for (const auto& [member, _] : channel->GetUsers())
            {
                TagUsageExtItem::TagStats* stats = tag_stats.Get(member);
                if (stats && (stats->fileupload_count || stats->conference_count || stats->tictactoe_count))
                {
                    user_count++;
                }
            }
            
            if (user_count > 0)
            {
                user->WriteNotice("*** " + ConvToStr(user_count) + 
                                 " users in " + channel->name + 
                                 " have been using KiwiIRC features. Use /STATS K for details.");
            }
        }
    }

    void OnModuleRehash(User* user, const std::string& param) override
    {
        if (param == "kiwiirctags")
        {
            user->WriteNotice("*** Rehashing KiwiIRC Tags module configuration");
        }
    }
};

MODULE_INIT(ModuleKiwiIRCTags)
