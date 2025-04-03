/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 * Copyright (C) 2025-03-12 revrsefr
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
 #include "modules/httpd.h"
 #include "modules/isupport.h"
 #include "modules/ssl.h"
 #include "fileutils.h"
 #include <map>
 
 class FilehostUploadHandler : public HTTPRequestEventListener
 {
  private:
     Module* mod;
     std::string uploadpath;
     std::string baseuri;
     std::map<std::string, std::string> accepted_mimetypes;
     bool authenticate;
 
  public:
     FilehostUploadHandler(Module* m, const std::string& uploaddir, const std::string& uri, bool auth)
         : HTTPRequestEventListener(m)
         , mod(m)
         , uploadpath(uploaddir)
         , baseuri(uri)
         , authenticate(auth)
     {
         // Create the upload directory if it doesn't exist
         if (!FileSystem::Exists(uploadpath))
         {
             FileSystem::CreateDirectory(uploadpath);
         }
         
         // Initialize accepted MIME types
         accepted_mimetypes["text/plain"] = "txt";
         accepted_mimetypes["text/html"] = "html";
         accepted_mimetypes["image/png"] = "png";
         accepted_mimetypes["image/jpeg"] = "jpg";
         accepted_mimetypes["image/gif"] = "gif";
         accepted_mimetypes["application/pdf"] = "pdf";
     }
 
     ModResult OnHTTPRequest(HTTPRequest& request) override
     {
         // Only handle requests to our specific endpoint and only POST for uploads
         if (request.GetPath() != baseuri)
             return MOD_RES_PASSTHRU;
 
         if (request.GetType() == "OPTIONS")
         {
             // Handle OPTIONS request for CORS and to indicate accepted MIME types
             HTTPHeaders headers;
             headers.SetHeader("Allow", "OPTIONS, POST");
             headers.SetHeader("Access-Control-Allow-Origin", "*");
             headers.SetHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
             headers.SetHeader("Access-Control-Allow-Headers", "Content-Type, Content-Disposition, Content-Length, Authorization");
             
             // Construct Accept-Post header with all valid MIME types
             std::string accept_post;
             for (const auto& [mimetype, ext] : accepted_mimetypes)
             {
                 if (!accept_post.empty())
                     accept_post += ", ";
                 accept_post += mimetype;
             }
             headers.SetHeader("Accept-Post", accept_post);
 
             // Send response
             std::stringstream response;
             request.sock->Page(&response, 200, &headers);
             return MOD_RES_DENY;
         }
         
         if (request.GetType() != "POST")
         {
             // Only POST method is allowed for file uploads
             HTTPHeaders headers;
             headers.SetHeader("Allow", "OPTIONS, POST");
             std::stringstream response;
             response << "<h1>405 Method Not Allowed</h1>";
             response << "<p>Only POST requests are allowed for file uploads</p>";
             request.sock->Page(&response, 405, &headers);
             return MOD_RES_DENY;
         }
         
         // Handle authentication if required
         if (authenticate)
         {
             // Get Authorization header
             std::string auth_header = request.headers->GetHeader("Authorization");
             if (auth_header.empty())
             {
                 // Authorization required
                 HTTPHeaders headers;
                 headers.SetHeader("WWW-Authenticate", "Basic realm=\"InspIRCd FileHost\"");
                 std::stringstream response;
                 response << "<h1>401 Unauthorized</h1>";
                 response << "<p>Authentication is required to upload files</p>";
                 request.sock->Page(&response, 401, &headers);
                 return MOD_RES_DENY;
             }
             
             // Simple auth check - in a real implementation we will check
             // against the same credentials used on the IRC connection
         
         // Get content type and check if it's accepted
         std::string content_type = request.headers->GetHeader("Content-Type");
         std::string file_ext = "bin";
         bool valid_type = false;
         
         // Check if the content type is in our list of accepted types
         auto it = accepted_mimetypes.find(content_type);
         if (it != accepted_mimetypes.end())
         {
             file_ext = it->second;
             valid_type = true;
         }
         
         // If not an accepted type, reject the upload
         if (!valid_type)
         {
             std::stringstream response;
             response << "<h1>415 Unsupported Media Type</h1>";
             response << "<p>The provided content type is not supported</p>";
             request.sock->Page(&response, 415, request.headers);
             return MOD_RES_DENY;
         }
         
         // Get Content-Disposition header for the filename
         std::string filename;
         std::string content_disp = request.headers->GetHeader("Content-Disposition");
         
         if (!content_disp.empty())
         {
             // Extract filename from Content-Disposition
             size_t filename_pos = content_disp.find("filename=\"");
             if (filename_pos != std::string::npos)
             {
                 filename_pos += 10; // Length of 'filename="'
                 size_t end_pos = content_disp.find("\"", filename_pos);
                 if (end_pos != std::string::npos)
                 {
                     filename = content_disp.substr(filename_pos, end_pos - filename_pos);
                 }
             }
         }
         
         // Generate a random filename if none was provided
         if (filename.empty())
         {
             std::string random_str = ServerInstance->GenRandomStr(16);
             filename = random_str + "." + file_ext;
         }
         else
         {
             // Sanitize the filename to prevent directory traversal
             size_t slash_pos;
             while ((slash_pos = filename.find('/')) != std::string::npos)
                 filename[slash_pos] = '_';
             while ((slash_pos = filename.find('\\')) != std::string::npos)
                 filename[slash_pos] = '_';
         }
         
         // Ensure the file has the correct extension
         if (!filename.empty() && filename.find('.') == std::string::npos)
         {
             filename += "." + file_ext;
         }
         
         // Form the full path
         std::string fullpath = uploadpath + "/" + filename;
         
         // Write the file
         try
         {
             FileWriter fw(fullpath);
             fw.WriteString(request.GetPostData());
         }
         catch (const CoreException& ex)
         {
             ServerInstance->Logs.Log(MODNAME, LOG_DEFAULT, "Error writing uploaded file %s: %s", 
                 fullpath.c_str(), ex.GetReason().c_str());
             std::stringstream response;
             response << "<h1>500 Internal Server Error</h1>";
             response << "<p>Failed to write uploaded file: " << ex.GetReason() << "</p>";
             request.sock->Page(&response, 500, request.headers);
             return MOD_RES_DENY;
         }
         
         // Form the public URL of the uploaded file
         std::string server_hostname = ServerInstance->Config->ServerName;
         std::string public_url = baseuri + "/" + filename;
         if (baseuri.back() == '/')
             public_url = baseuri + filename;
         
         // Send the response with the URL to the uploaded file
         HTTPHeaders headers;
         headers.SetHeader("Location", public_url);
         headers.SetHeader("Content-Type", "text/plain");
         
         std::stringstream response;
         response << public_url;
         
         request.sock->Page(&response, 201, &headers);
         return MOD_RES_DENY;
     }
 };
 
 class FilehostGetHandler : public HTTPRequestEventListener
 {
  private:
     Module* mod;
     std::string uploadpath;
     std::string baseuri;
 
  public:
     FilehostGetHandler(Module* m, const std::string& uploaddir, const std::string& uri)
         : HTTPRequestEventListener(m)
         , mod(m)
         , uploadpath(uploaddir)
         , baseuri(uri)
     {
     }
 
     ModResult OnHTTPRequest(HTTPRequest& request) override
     {
         // Should start with the base URI but not equal to it (we want a file)
         if (request.GetPath() == baseuri || !insp::starts_with(request.GetPath(), baseuri))
             return MOD_RES_PASSTHRU;
 
         if (request.GetType() != "GET" && request.GetType() != "HEAD")
             return MOD_RES_PASSTHRU;
 
         // Extract the filename from the path
         std::string filepath = request.GetPath().substr(baseuri.length());
         
         // Remove leading slashes
         while (!filepath.empty() && filepath[0] == '/')
             filepath = filepath.substr(1);
         
         // Prevent directory traversal
         size_t slash_pos;
         while ((slash_pos = filepath.find('/')) != std::string::npos)
             filepath[slash_pos] = '_';
         while ((slash_pos = filepath.find('\\')) != std::string::npos)
             filepath[slash_pos] = '_';
         
         // Form the full path
         std::string fullpath = uploadpath + "/" + filepath;
 
         // Check if the file exists
         if (!FileSystem::Exists(fullpath) || FileSystem::GetFileSize(fullpath) == -1)
         {
             std::stringstream response;
             response << "<h1>404 Not Found</h1>";
             response << "<p>The requested file was not found</p>";
             request.sock->Page(&response, 404, request.headers);
             return MOD_RES_DENY;
         }
 
         // Get MIME type based on file extension
         std::string mime_type = "application/octet-stream";
         size_t dot_pos = filepath.find_last_of('.');
         if (dot_pos != std::string::npos)
         {
             std::string ext = filepath.substr(dot_pos + 1);
             
             // Basic MIME type mapping based on extension
             if (ext == "txt")
                 mime_type = "text/plain";
             else if (ext == "html" || ext == "htm")
                 mime_type = "text/html";
             else if (ext == "png")
                 mime_type = "image/png";
             else if (ext == "jpg" || ext == "jpeg")
                 mime_type = "image/jpeg";
             else if (ext == "gif")
                 mime_type = "image/gif";
             else if (ext == "pdf")
                 mime_type = "application/pdf";
         }
 
         // Set up headers
         HTTPHeaders headers;
         headers.SetHeader("Content-Type", mime_type);
         
         // If it's a HEAD request, just respond with headers
         if (request.GetType() == "HEAD")
         {
             std::stringstream empty_response;
             request.sock->Page(&empty_response, 200, &headers);
             return MOD_RES_DENY;
         }
 
         // Read and serve the file content
         try
         {
             FileReader fr(fullpath);
             std::stringstream response;
             response << fr.GetString();
             request.sock->Page(&response, 200, &headers);
         }
         catch (const CoreException& ex)
         {
             ServerInstance->Logs.Log(MODNAME, LOG_DEFAULT, "Error reading file %s: %s", 
                 fullpath.c_str(), ex.GetReason().c_str());
             std::stringstream response;
             response << "<h1>500 Internal Server Error</h1>";
             response << "<p>Failed to read file: " << ex.GetReason() << "</p>";
             request.sock->Page(&response, 500, request.headers);
         }
         
         return MOD_RES_DENY;
     }
 };
 
 class ModuleFileHost : public Module, public ISupport::EventListener
 {
  private:
     std::string uploadpath;
     std::string baseuri;
     std::string public_url;
     
     bool authenticate;
     bool require_ssl;
     
     HTTPdAPI API;
     FilehostUploadHandler* uploadhandler = nullptr;
     FilehostGetHandler* gethandler = nullptr;
 
  public:
     ModuleFileHost()
         : Module(VF_VENDOR, "Provides a file hosting service for users to upload and share files on IRC")
         , ISupport::EventListener(this)
         , API(this)
     {
     }
 
     ~ModuleFileHost()
     {
         delete uploadhandler;
         delete gethandler;
     }
 
     void ReadConfig(ConfigStatus& status) override
     {
         const auto& tag = ServerInstance->Config->ConfValue("filehost");
         
         uploadpath = tag->getString("uploadpath", "data/uploads");
         baseuri = tag->getString("uri", "/upload");
         authenticate = tag->getBool("authenticate", true);
         require_ssl = tag->getBool("requiressl", true);
         
         // Ensure the base URI begins with a slash
         if (baseuri.empty() || baseuri[0] != '/')
             baseuri = "/" + baseuri;
         
         // Construct the full public URL
         std::string hostname = ServerInstance->Config->ServerName;
         int port = tag->getInt("port", 0);
         bool use_ssl = tag->getBool("ssl", true);
         
         // Determine protocol and port
         std::string protocol = use_ssl ? "https" : "http";
         
         // Construct the URL
         public_url = protocol + "://" + hostname;
         if (port > 0)
             public_url += ":" + std::to_string(port);
         public_url += baseuri;
         
         // Unregister old handlers if they exist
         if (uploadhandler)
         {
             delete uploadhandler;
             uploadhandler = nullptr;
         }
         
         if (gethandler)
         {
             delete gethandler;
             gethandler = nullptr;
         }
         
         // Create new handlers
         uploadhandler = new FilehostUploadHandler(this, uploadpath, baseuri, authenticate);
         gethandler = new FilehostGetHandler(this, uploadpath, baseuri);
     }
 
     void OnBuildISupport(ISupport::TokenMap& tokens) override
     {
         tokens["FILEHOST"] = public_url;
     }
 
     ModResult OnUserPreMessage(User* user, const MessageTarget& target, MessageDetails& details) override
     {
         // If we require SSL, check if users are trying to use FILEHOST over a non-SSL connection
         if (require_ssl)
         {
             LocalUser* localuser = IS_LOCAL(user);
             if (localuser && !localuser->eh.GetIOHook() && details.text.find(public_url) != std::string::npos)
             {
                 // User is trying to send a FILEHOST URL over a non-SSL connection
                 user->WriteNotice("You cannot send FILEHOST URLs over a non-SSL connection. Please use an SSL connection.");
                 return MOD_RES_DENY;
             }
         }
         return MOD_RES_PASSTHRU;
     }
 };
 
 MODULE_INIT(ModuleFileHost)
