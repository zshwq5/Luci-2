local i="shadowsocksr"
local h=require"luci.dispatcher"
local a,t,e
local m={
"table",
"rc4",
"rc4-md5",
"aes-128-cfb",
"aes-192-cfb",
"aes-256-cfb",
"bf-cfb",
"camellia-128-cfb",
"camellia-192-cfb",
"camellia-256-cfb",
"cast5-cfb",
"des-cfb",
"idea-cfb",
"rc2-cfb",
"seed-cfb",
"salsa20",
"chacha20",
"chacha20-ietf",
}
local p={
"origin",
"verify_simple",
"verify_sha1",
"auth_sha1",
"auth_sha1_v2",
"auth_sha1_v4",
"auth_aes128_md5",
"auth_aes128_sha1",
}
local o={
"plain",
"http_simple",
"http_post",
"tls1.2_ticket_auth",
}

arg[1]=arg[1]or""
a=Map(i,translate("Shadowsocksr Server Config"),
	translate("Server address allow ip address only.If you are using domain address,please transform it via ping it.").."<br />"..
	translate("If your server does not support ssr,please set \"protocol-origin;obfs-plain\" ."))
a.redirect=h.build_url("admin","services","shadowsocksr")
t=a:section(NamedSection,arg[1],"servers","")
t.addremove=false
t.dynamic=false
e=t:option(Value,"remarks",translate("Remarks"))
e.default="Shadowsocks"
e.rmempty=false
e=t:option(Value,"server",translate("Server Address"))
e.datatype="ipaddr"
e.rmempty=false
e=t:option(Value,"server_port",translate("Server Port"))
e.datatype="port"
e.rmempty=false
e=t:option(Value,"password",translate("Password"))
e.password=true
e.rmempty=false
e=t:option(ListValue,"method",translate("Encryption Method"))
for a,t in ipairs(m)do e:value(t)end
e.rmempty=false
e=t:option(Value,"timeout",translate("Timeout"))
e.datatype="uinteger"
e.default=300
e.rmempty=false
e=t:option(ListValue,"protocol",translate("Protocol"))
for a,t in ipairs(p)do e:value(t)end
e.rmempty=false
e=t:option(ListValue,"obfs",translate("Obfs Param"),
	"<a href=\"https://github.com/breakwa11/shadowsocks-rss/blob/master/ssr.md\">" ..
	translate("shadowsocksr document") ..
	"</a>")
for a,t in ipairs(o)do e:value(t)end
e.rmempty=false
e = t:option(Flag, "plugin_param", translate("plugin parameter"),
	translate("Warning！Mistaken use of this parameter may cause the server ip to be blocked."))
e:depends("obfs", "http_simple")
e:depends("obfs", "tls1.2_ticket_auth")
e = t:option(Value, "obfs_param", translate("obfs parameter"))
e.rmempty = true
e.datatype = "host"
e:depends("plugin_param", "1")
return a
