local c,b,l,d,a,s,e
local i=require"luci.dispatcher"
local k=require("luci.model.ipkg")
local h=luci.model.uci.cursor()
local nwm = require("luci.model.network").init()
local c={}
h:foreach("shadowsocksr","servers",function(e)
if e.server and e.remarks and e.server_port then
c[e[".name"]]="%s [%s:%s]"%{e.remarks,e.server,e.server_port}
end
end)

local b={
{bin="ssr-redir",name="ssr-redir"},
{bin="ssr-local",name="ssr-local"},
{bin="ssr-tunnel",name="ssr-tunnel"},
{bin="pdnsd",name="pdnsd"},
{bin="Pcap_DNSProxy",name="pcap-dnsproxy"}
}

local l={
{id="B",name="Disable Proxy"},
{id="M",name="GFW-List based auto-proxy"},
{id="S",name="All non-China IPs"},
{id="G",name="All Public IPs"},
{id="V",name="Watching Youku overseas"}
}

local d={
{id="D",bin="pdnsd",name="pdnsd mode"},
{id="P",bin="pcap-dnsproxy",name="pcap-dnsproxy mode"},
{id="Q",bin="pcap-dnsproxy",name="enhanced mode: pcap-dnsproxy+socks5"},
{id="F",name="enhanced mode: pdnsd+pcap-dnsproxy"},
{id="U",bin="iptables-mod-tproxy",name="udp relay"},
{id="R",name="enhanced mode: pdnsd+udp relay"}
}

g="<b><font color=\"green\">" .. translate("Running") .. "</font></b>"
r="<b><font color=\"red\">" .. translate("Not running") .. "</font></b>"

function is_installed(e)
return k.installed(e)
end

function has_bin(e)
	return luci.sys.call("command -v %s >/dev/null" %{e}) == 0
end

function is_running(e)
	return luci.sys.call("pidof %s >/dev/null" %{e}) == 0
end

m = Map("shadowsocksr", translate("Shadowsocksr Transparent Proxy"),
	translate("A fast secure tunnel proxy that help you get through firewalls on your router"))
m.redirect=i.build_url("admin","services","shadowsocksr")

s = m:section(TypedSection, "status", translate("Running Status"))
s.anonymous = true

for _,v in pairs(b) do
	if has_bin(v.bin) then
		if is_running(v.bin) then
		e = s:option(DummyValue, "_status",translate(v.name) .. " - " .. g .."<br /> ")
		else
		e = s:option(DummyValue, "_status",translate(v.name) .. " - " .. r .."<br /> ")
		end
	end
end

s = m:section(TypedSection, "global", translate("Global Setting"))
s.anonymous = true

-- ---------------------------------------------------
e = s:option(Flag, "enabled", translate("Enable"))
e.rmempty = false

e=s:option(ListValue,"global_server",translate("Choose Server"))
e.default="nil"
e.rmempty=false
e:value("nil",translate("Disable"))
for i,v in pairs(c)do e:value(i,v)end

e = s:option(ListValue, "proxy_mode", translate("Proxy Mode"),
	translate("GFW-List mode requires flushing DNS cache") .. "<br /> " ..
	"<a href=\"" .. luci.dispatcher.build_url("admin", "services", "gfwlist") .. "\">" ..
	translate("Click here to customize your GFW-List") ..
	"</a>")
e.default="S"
for _,v in pairs(l) do e:value(v.id,translate(v.name))end

e = s:option(ListValue, "dns_mode", translate("Dns resolution"),
	translate("used to prevent DNS pollution."))
e.default="D"
for _,v in pairs(d) do
if v.id ~= "F" and v.id ~= "R" then
	if is_installed(v.bin) then
	e:value(v.id,translate(v.name))
	end
elseif v.id == "F" then
	if is_installed("pcap-dnsproxy") and is_installed("pdnsd") then
	e:value(v.id,translate(v.name))
	end
else
	if is_installed("iptables-mod-tproxy") and is_installed("pdnsd") then
	e:value(v.id,translate(v.name))
	end
end
end

s = m:section(TypedSection, "upstream_dns", translate("Upstream DNS"),
	translate("When using pdnsd,below will be pdnsd's upstream dns server") .."<br /> " ..
	translate("When using udp relay mode,please set below to your udp dns request server") .."<br /> " ..
	translate("When using pure pcap mode,below makes no use") .."<br /> " ..
	translate("If you have no idea how to config,please keep it default."))
s.anonymous = true

e = s:option(Value, "safe_dns", translate("Safe DNS"),
	translate("8.8.8.8 or 8.8.4.4 is recommended"))
e.datatype = "ip4addr"
e.placeholder = "8.8.8.8"
e.optional = false

e = s:option(Value, "safe_dns_port", translate("Safe DNS Port"),
	translate("Foreign DNS on UDP port 53 might be polluted"))
e.datatype = "range(1,65535)"
e.placeholder = "53"
e.optional = false
------------------------------------------------------
-- [[ LAN Hosts ]]--
s = m:section(TypedSection, "lan_hosts", translate("Proxy Control"),
	translate("Controling proxy request for particular device.").."<br /> " ..
	translate("In addition to the following device,the others will use global setting."))
s.template = "cbi/tblsection"
s.addremove = true
s.anonymous = true

e = s:option(Value, "host", translate("Host"))
luci.sys.net.arptable(function(x)
	e:value(x["IP address"], "%s (%s)" %{x["IP address"], x["HW address"]})
end)
e.datatype = "ip4addr"
e.rmempty = false
e.width="1%"

e = s:option(ListValue, "type", translate("Proxy Mode"))
for _,v in pairs(l) do e:value(v.id,translate(v.name))end
e.rmempty = false
e.width="1%"

e = s:option(Flag, "enable", translate("Enable"))
e.default = "1"
e.rmempty = false

-- ---------------------------------------------------
s=m:section(TypedSection,"servers",translate("Servers List"))
s.anonymous=true
s.addremove=true
s.template="cbi/tblsection"
s.extedit=i.build_url("admin","services","shadowsocksr","serverconfig","%s")
function s.create(e,s)
local e=TypedSection.create(e,s)
luci.http.redirect(i.build_url("admin","services","shadowsocksr","serverconfig",e))
end
function s.remove(s,a)
s.map.proceed=true
s.map:del(a)
luci.http.redirect(i.build_url("admin","services","shadowsocksr"))
end
e=s:option(DummyValue,"remarks",translate("Remarks"))
e.width="30%"
e=s:option(DummyValue,"server",translate("Server Address"))
e.width="20%"
e=s:option(DummyValue,"server_port",translate("Server Port"))
e.width="10%"
e=s:option(DummyValue,"method",translate("Encryption Method"))
e.width="15%"
e=s:option(DummyValue,"protocol",translate("Protocol"))
e.width="15%"
e=s:option(DummyValue,"obfs",translate("Obfs Param"))
e.width="10%"

return m
