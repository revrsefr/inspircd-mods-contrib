# InspIRCd 4 Contrib Modules

Custom modules for InspIRCd 4. Some are original, some are inspired by others.
Use at your own risk; several are still work in progress.

## Modules

### m_allsend
- Description: Adds the /ALLSEND command for opers to send messages to specific groups of users.
- Config: <module name="allsend">
- Libs: None

### m_censorplus
- Description: No $ModDesc in source.
- Config: None
- Libs: icu-uc, icu-i18n, -L/usr/local/lib -lhs

### m_changeidentonick
- Description: Sets the user's ident to match their nickname on connect.
- Config: None
- Libs: None

### m_detect_fake_websocket
- Description: Warns IRC operators and Z-lines botnets trying to use WebSockets.
- Config: None
- Libs: None

### m_extbanbanlist
- Description: Provides extban 'b' - Ban list from another channel
- Config: None
- Libs: None

### m_extbanredirect
- Description: Provide extended ban <extbanchar>:<chan>:<mask> to redirect users to another channel
- Config: <extbanredirect char="d">
- Libs: None

### m_geomaxlite
- Description: Adds city and country information to WHOIS using the MaxMind database and it's usermode +y.
- Config: <geolite dbpath="path/geodata/GeoLite2-City.mmdb">
- Libs: -lmaxminddb

### m_hashident
- Description: Sets the user's ident to HMAC-SHA256 hash of their IP address + SECRET_KEY
- Config: None
- Libs: None

### m_hidewhois
- Description: Provides the ability to hide whois information from users.
- Config: <hidewhois opers="yes" selfview="yes" hide_server="yes" hide_idle="yes" hide_away="yes" hide_geolocation="yes" hide_secure="yes">
- Libs: None

### m_ircv3_FILEHOST
- Description: Provides the DRAFT FILEHOST IRCv3 extension.
- Config: None
- Libs: -lcrypto -lssl

### m_ircv3_extended_isupport
- Description: Provides the DRAFT draft/extended-isupport IRCv3 extension.
- Config: None
- Libs: None

### m_ircv3_kiwiirctags
- Description: Provides support for KiwiIRC-specific tags
- Config: <kiwiirctags enablefileupload="yes" enableconference="yes" enabletictactoe="yes" logusage="no" maxuploadsize="10M" restrictconferenceto="oper" notifychannelops="yes" notificationformat="%source% is using %tagtype% in %channel%">
- Libs: None

### m_ircv3_metadata
- Description: Provides the METADATA IRCv3 extension.
- Config: <module name="m_ircv3_metadata">
- Config: <ircv3metadata penalty="2000" maxkeys="100" maxsubs="10" maxvaluebytes="1024" maxsyncwork="10000" syncretryafter="15" beforeconnect="yes">
- Config: <ircv3metadata operonly="yes" maxsubs="50" maxsyncwork="25000" syncretryafter="5">
- Config: <ircv3metadatakey name="secret/*" set="no" view="oper" visibility="oper-only">
- Config: <ircv3metadatakey name="internal/*" set="yes" view="oper" visibility="oper-only">
- Config: <ircv3metadatakey name="public/*" set="yes" view="all" visibility="*">
- Libs: None

### m_ircv3_metadata_db
- Description: Persists IRCv3 draft/metadata-2 user/channel metadata to disk.
- Config: <module name="m_ircv3_metadata_db">
- Config: <ircv3metadatadb filename="metadata.db" saveperiod="300" backoff="0" maxbackoff="36000" expireafter="0" users="yes" channels="permanent" maxuserentries="50000" maxchanentries="5000">
- Libs: None

### m_ircv3_multiline
- Description: No $ModDesc in source.
- Config: None
- Libs: None

### m_ircv3_noimplicitnames
- Description: IRCV3 draft/no-implicit-names.
- Config: None
- Libs: None

### m_ircv3_sni
- Description: No $ModDesc in source.
- Config: None
- Libs: None

### m_ssl_gnutls
- Description: Provides TLS using GnuTLS with SNI-based profile selection.
- Config: <sslprofile name="gnutls-default" provider="gnutls" certfile="certs/default.pem" keyfile="certs/default.key">
- Config: <sslprofile name="gnutls-example" provider="gnutls" certfile="certs/example.pem" keyfile="certs/example.key">
- Config: <sni host="irc.example.net" sslprofile="gnutls-example">
- Libs: -lgnutls

### m_ssl_openssl
- Description: Provides TLS using OpenSSL with SNI-based profile selection.
- Config: <sslprofile name="openssl-default" provider="openssl" certfile="certs/default.pem" keyfile="certs/default.key">
- Config: <sslprofile name="openssl-example" provider="openssl" certfile="certs/example.pem" keyfile="certs/example.key">
- Config: <sni host="irc.example.net" sslprofile="openssl-example">
- Libs: -lssl -lcrypto

### m_profileLink
- Description: Adds a profile link to the WHOIS response for registered users, ignoring services, bots.
- Config: <profilelink baseurl="https://example.com/profil/">
- Libs: None

### m_randomidxlines
- Description: Enhances /zline, /gline, /kline, /kill and similar commands by adding a random ID to the end for better log identification.
- Config: None
- Libs: None

### m_recaptchat
- Description: Google reCAPTCHA v2 verification via JWT with HTTP backend check.
- Config: <captchaconfig url="https://chaat.site/recaptcha/verify/">
- Libs: -lcrypto -lcurl

### m_reputation
- Description: Tracks IP reputation and provides a score-based extban.
- Config: <reputation database="reputation.db" ipv4prefix="32" ipv6prefix="64" bumpinterval="5m" expireinterval="605" saveinterval="902" minchanmembers="3" scorecap="10000" whois="all">
- Libs: None

### m_securitygroups
- Description: Implements UnrealIRCd-style security-groups for InspIRCd 4.
- Config: <securitygroup name="example" mask="*@example.com" account="no" tls="no" insecure="no" websocket="no" webirc="no" public="yes">
- Libs: None

### m_solvemsg
- Description: Requires users to solve a basic maths problem before messaging others.
- Config: <solvemsg chanmsg="no" usermsg="yes" exemptregistered="yes" warntime="60s" warnintro="..." warnquestion="..." warnhowto="...">
- Libs: None

### m_whoisport
- Description: Adds the port and connect class of the user to WHOIS for operators only.
- Config: None
- Libs: None

### m_wiki
- Description: Store wiki slug of wikipages of the network.
- Config: None
- Libs: None

## Notes
- Config entries above are copied from each module's $ModConfig comments.
- Libs come from $LinkerFlags lines where present.

## Contact
- IRC Server: irc.irc4fun.net +6697 (tls)
- Channel: #development
