/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 * Copyright (C) 2025-04-12 reverse
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
/// $ModDesc: Provides the DRAFT FILEHOST IRCv3 extension.


/// $LinkerFlags: -lcrypto -lssl


#include "inspircd.h"
#include "modules/cap.h"
#include "modules/ctctags.h"
#include "modules/isupport.h"
#include "modules/ssl.h"
#include "modules/account.h"
#include "modules/ircv3.h"
#include "clientprotocolmsg.h"
#include <jwt-cpp/jwt.h>


// File type enumeration for metadata
enum FileType
{
    FILE_UNKNOWN,
    FILE_IMAGE,
    FILE_TEXT,
    FILE_BINARY,
    FILE_ARCHIVE,
    FILE_DOCUMENT
};

// JWT wrapper class using jwt-cpp library
class JWT
{
 public:
    static std::string Generate(const std::string& username, const std::string& secret, const std::string& issuer, time_t expiry)
    {
        // Simplified token generation using the provided issuer
        auto token = jwt::create()
            .set_issuer(issuer)
            .set_subject(username)
            .set_issued_at(std::chrono::system_clock::from_time_t(ServerInstance->Time()))
            .set_expires_at(std::chrono::system_clock::from_time_t(expiry))
            .sign(jwt::algorithm::hs256{secret});

        return token;
    }

    static bool Verify(const std::string& token, const std::string& secret, const std::string& issuer)
    {
        try
        {
            // Verify the token with the provided secret and issuer
            auto verifier = jwt::verify()
                .allow_algorithm(jwt::algorithm::hs256{secret})
                .with_issuer(issuer);

            auto decoded = jwt::decode(token);
            verifier.verify(decoded);

            return true;
        }
        catch (const std::exception&)
        {
            return false;
        }
    }
    
    static std::string GetUsername(const std::string& token)
    {
        try
        {
            auto decoded = jwt::decode(token);
            return decoded.get_subject();
        }
        catch (const std::exception&)
        {
            return "";
        }
    }
    
    static std::string GetIssuer(const std::string& token)
    {
        try
        {
            auto decoded = jwt::decode(token);
            return decoded.get_issuer();
        }
        catch (const std::exception&)
        {
            return "";
        }
    }
};

// Filehost message tag provider
class FileHostTag final : public ClientProtocol::MessageTagProvider
{
 private:
    Cap::Capability& cap;

 public:
    FileHostTag(Module* Creator, Cap::Capability& Cap)
        : ClientProtocol::MessageTagProvider(Creator)
        , cap(Cap)
    {
    }

    ModResult OnProcessTag(User* user, const std::string& tagname, std::string& tagvalue) override
    {
        if (tagname != "reverse.im/filehost")
            return MOD_RES_PASSTHRU;

        // Only allow servers to set this tag
        if (IS_LOCAL(user))
            return MOD_RES_DENY;

        return MOD_RES_ALLOW;
    }

    bool ShouldSendTag(LocalUser* user, const ClientProtocol::MessageTagData& tagdata) override
    {
        return cap.IsEnabled(user);
    }
};

class CommandFilehost : public SplitCommand
{
 private:
    std::string& public_url;
    std::string& jwt_secret;
    std::string& jwt_issuer;
    unsigned int token_expiry;
    
 public:
    std::string filehost_auth_msg;  // Made public so it can be accessed by the Module class
    
    CommandFilehost(Module* parent, std::string& url, std::string& secret, std::string& issuer, unsigned int expiry)
        : SplitCommand(parent, "FILEHOST", 0)
        , public_url(url)
        , jwt_secret(secret)
        , jwt_issuer(issuer)
        , token_expiry(expiry)
    {
        syntax.push_back("[info]");
        penalty = 2;  // Small penalty to prevent abuse
        filehost_auth_msg = ServerInstance->Config->ConfValue("filehost")->getString("auth_message", "Use /msg NickServ IDENTIFY password to log in.");
    }

    CmdResult HandleLocal(LocalUser* user, const Params& parameters) override
    {
        // Check if the user is identified with services (account)
        const std::string* accountname = nullptr;
        
        Account::API accountapi(this->creator);
        if (accountapi && *accountapi)
        {
            accountname = (*accountapi)->GetAccountName(user);
        }

        if (!accountname || accountname->empty())
        {
            user->WriteNotice("*** You must be logged in to use file hosting. " + filehost_auth_msg);
            return CmdResult::FAILURE;
        }

        // Simplified token generation using the existing JWT::Generate method
        time_t expiry = ServerInstance->Time() + token_expiry;
        std::string token = JWT::Generate(user->nick, jwt_secret, jwt_issuer, expiry);
        std::string auth_url = public_url + "/upload?token=" + token;

        // User is authorized, send file upload instructions with JWT token
        if (parameters.empty())
        {
            user->WriteNotice("*** FILEHOST: Upload files using " + auth_url);
            user->WriteNotice("*** FILEHOST: You're already authenticated through IRC! No need to log in again.");
            user->WriteNotice("*** FILEHOST: Share files with others using " + public_url + "/files/filename");
            user->WriteNotice("*** FILEHOST: Your logged in account: " + *accountname);
            user->WriteNotice("*** FILEHOST: Your upload link is valid for " + ConvToStr(token_expiry / 60) + " minutes");
            return CmdResult::SUCCESS;
        }
        else if (parameters[0] == "info")
        {
            user->WriteNotice("*** FILEHOST: Service provided by " + public_url);
            user->WriteNotice("*** FILEHOST: Maximum file size: 16MB");
            user->WriteNotice("*** FILEHOST: Allowed file types: txt, pdf, png, jpg, jpeg, gif, html, htm, css, js, svg");
            return CmdResult::SUCCESS;
        }

        user->WriteNotice("*** FILEHOST: Unknown parameter. Use /FILEHOST without parameters for help.");
        return CmdResult::SUCCESS;
    }
};

class ModuleFileHost : public Module, public ISupport::EventListener, public Cap::Capability, public CTCTags::EventListener
{
 private:
    std::string public_url;
    bool require_ssl;
    std::string jwt_secret;
    std::string jwt_issuer;
    unsigned int token_expiry;
    CommandFilehost cmd;
    FileHostTag filetag;
    Events::ModuleEventProvider tagevprov;
    CTCTags::CapReference ctctagcap;
    
    // Helper to determine file type from extension
    FileType GetFileTypeFromExtension(const std::string& filename) const
    {
        std::string ext;
        size_t dot_pos = filename.rfind('.');
        
        if (dot_pos != std::string::npos)
            ext = filename.substr(dot_pos + 1);
            
        if (ext.empty())
            return FILE_UNKNOWN;
            
        // Convert to lowercase for comparison
        std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
        
        // Image formats
        if (ext == "png" || ext == "jpg" || ext == "jpeg" || ext == "gif" || ext == "svg")
            return FILE_IMAGE;
            
        // Text formats
        if (ext == "txt" || ext == "html" || ext == "htm" || ext == "css" || ext == "js")
            return FILE_TEXT;
            
        // Document formats
        if (ext == "pdf" || ext == "doc" || ext == "docx")
            return FILE_DOCUMENT;
            
        // Archive formats
        if (ext == "zip" || ext == "tar" || ext == "gz" || ext == "rar")
            return FILE_ARCHIVE;
            
        return FILE_BINARY;
    }
    
    // Extract filename from URL
    std::string GetFilenameFromURL(const std::string& url) const
    {
        // Check if it's our filehost URL
        if (url.find(public_url + "/files/") != 0)
            return "";
            
        // Extract the filename part
        std::string filename = url.substr((public_url + "/files/").length());
        
        // Remove any query parameters
        size_t qmark = filename.find('?');
        if (qmark != std::string::npos)
            filename = filename.substr(0, qmark);
            
        return filename;
    }
    
    // Create metadata for file
    void AddFileMetadataTags(ClientProtocol::TagMap& tags, const std::string& url)
    {
        std::string filename = GetFilenameFromURL(url);
        if (filename.empty())
            return;
            
        FileType type = GetFileTypeFromExtension(filename);
        
        // Create JSON metadata structure
        std::string metadata = "{\"url\":\"" + url + "\",\"filename\":\"" + filename + "\"";
        
        // Add file type
        switch (type)
        {
            case FILE_IMAGE:
                metadata += ",\"type\":\"image\"";
                break;
            case FILE_TEXT:
                metadata += ",\"type\":\"text\"";
                break;
            case FILE_DOCUMENT:
                metadata += ",\"type\":\"document\"";
                break;
            case FILE_ARCHIVE:
                metadata += ",\"type\":\"archive\"";
                break;
            case FILE_BINARY:
                metadata += ",\"type\":\"binary\"";
                break;
            default:
                metadata += ",\"type\":\"unknown\"";
        }
        
        metadata += "}";
        
        // Add tag to tagmap
        tags.emplace("reverse.im/filehost", ClientProtocol::MessageTagData(&filetag, metadata));
    }

    void SendTagMsg(User* user, const std::string& url, const std::string& metadata)
    {
        // Create a tag map to hold the metadata
        ClientProtocol::TagMap tags;
        AddFileMetadataTags(tags, url);

        // Corrected to use CTCTags::TagMessage directly.
        CTCTags::TagMessage tagmsg(user, "*", tags);
        // Wrap the CTCTags::TagMessage in a ClientProtocol::Event and send it.
        ClientProtocol::Event tagEvent(ServerInstance->GetRFCEvents().privmsg, tagmsg);
        for (const auto& [_, current_user] : ServerInstance->Users.GetUsers()) {
            LocalUser* localuser = IS_LOCAL(current_user);
            if (localuser && ctctagcap.IsEnabled(localuser)) {
                localuser->Send(tagEvent);
            }
        }
    }

 public:
    ModuleFileHost()
        : Module(VF_VENDOR, "Provides information about the external file hosting service for users to upload and share files on IRC")
        , ISupport::EventListener(this)
        , Cap::Capability(this, "reverse.im/filehost")
        , CTCTags::EventListener(this)
        , cmd(this, public_url, jwt_secret, jwt_issuer, token_expiry)
        , filetag(this, *this)
        , tagevprov(this, "event/filehost")
        , ctctagcap(this)
    {
    }

    void ReadConfig(ConfigStatus& status) override
    {
        const auto& tag = ServerInstance->Config->ConfValue("filehost");
        
        require_ssl = tag->getBool("requiressl", true);
        
        // Get the public URL from configuration
        public_url = tag->getString("website", "https://filehost.example.com");
        
        // Ensure the URL doesn't end with a trailing slash
        if (!public_url.empty() && public_url.back() == '/')
            public_url.pop_back();
            
        // Get the JWT secret from configuration
        jwt_secret = tag->getString("jwt_secret", "defaultsecret");
        
        // Get the JWT issuer from configuration
        jwt_issuer = tag->getString("jwt_issuer", "FILEHOST");
        
        // Get the token expiry time from configuration (default to 1 hour)
        token_expiry = tag->getNum<unsigned int>("token_expiry", 3600, 60, 86400);
        
        // Update command authentication message if config changes
        std::string new_auth_msg = tag->getString("auth_message", "Use /msg NickServ IDENTIFY password to log in.");
        cmd.filehost_auth_msg = new_auth_msg;
    }

    void OnBuildISupport(ISupport::TokenMap& tokens) override
    {
        tokens["reverse.im/FILEHOST"] = public_url;
    }

    ModResult OnUserPreMessage(User* user, MessageTarget& target, MessageDetails& details) override
    {
        // If we require SSL, check if users are trying to use FILEHOST over a non-SSL connection
        if (require_ssl)
        {
            LocalUser* localuser = IS_LOCAL(user);
            if (localuser && !localuser->eh.GetIOHook() && 
                (details.text.find(public_url) != std::string::npos))
            {
                // User is trying to send a FILEHOST URL over a non-SSL connection
                user->WriteNotice("You cannot send FILEHOST URLs over a non-SSL connection. Please use an SSL connection.");
                return MOD_RES_DENY;
            }
        }
        
        // Simple check for filehost URLs
        bool has_url = false;
        std::string url;
        size_t start_pos = std::string::npos;
        
        // Check for both your configured domain and hardcoded domain
        if (details.text.find(public_url + "/files/") != std::string::npos) 
        {
            start_pos = details.text.find(public_url + "/files/");
            has_url = true;
        }
    
        if (has_url)
        {
            // Extract the complete URL
            size_t end_pos = details.text.find_first_of(" \r\n", start_pos);
            if (end_pos == std::string::npos)
                end_pos = details.text.length();
                
            url = details.text.substr(start_pos, end_pos - start_pos);
            
            // Simple clean up of URL (remove trailing punctuation)
            const std::string punctuation = ",.;:!?'\"()[]{}";
            while (!url.empty() && punctuation.find(url.back()) != std::string::npos)
            {
                url.pop_back();
            }
            
            // Extract filename from URL
            std::string filename;
            if (url.find(public_url + "/files/") != std::string::npos)
            {
                filename = url.substr((public_url + "/files/").length());
            }
  
            // Create JSON metadata with file info
            std::string metadata = "{\"url\":\"" + url + "\"";
            
            // Add filename if available
            if (!filename.empty())
            {
                metadata += ",\"filename\":\"" + filename + "\"";
                
                // Try to determine file type based on extension
                std::string ext;
                size_t dot_pos = filename.rfind('.');
                if (dot_pos != std::string::npos)
                {
                    ext = filename.substr(dot_pos + 1);
                    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
                    
                    // Add file type if we can determine it
                    if (ext == "png" || ext == "jpg" || ext == "jpeg" || ext == "gif" || ext == "svg")
                    {
                        metadata += ",\"type\":\"image\"";
                    }
                    else if (ext == "txt" || ext == "md" || ext == "html" || ext == "htm")
                    {
                        metadata += ",\"type\":\"text\"";
                    }
                    else if (ext == "pdf" || ext == "doc" || ext == "docx")
                    {
                        metadata += ",\"type\":\"document\"";
                    }
                }
            }
            
            // Close the JSON object
            metadata += "}";
            
            // Add tag directly to message using emplace instead of operator[]
            details.tags_out.emplace("reverse.im/filehost", ClientProtocol::MessageTagData(&filetag, metadata));
            
            // Send TAGMSG to the user
            SendTagMsg(user, url, metadata);
            
            ServerInstance->Logs.Debug(MODNAME, "Added tag to message with URL: {}", url);
        }
        
        return MOD_RES_PASSTHRU;
    }
    
    void OnUserPostNick(User* user, const std::string& oldnick) override
    {
        // If the user is identified and changes their nick, remind them about filehost
        const std::string* accountname = nullptr;
        
        Account::API accountapi(this);
        if (accountapi && *accountapi)
        {
            accountname = (*accountapi)->GetAccountName(user);
            if (accountname && !accountname->empty())
            {
                user->WriteNotice("*** Remember: You can use /FILEHOST to get upload info for sharing files");
            }
        }
    }

    const std::string* GetValue(LocalUser* user) const override
    {
        return &public_url;
    }
};

MODULE_INIT(ModuleFileHost)
