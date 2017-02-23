--Mr.Z<zenghuaguo@hotmail.com>
local NXFS = require "nixio.fs"
local SYS  = require "luci.sys"
local UT = require "luci.util"
local ver = UT.trim(SYS.exec("vlmcsd -V | awk '/built/{print $2}' | sed -n 's/,//p'"))
--local ver = UT.trim(SYS.exec("vlmcsd -V | awk '/built/{print $1 \" \" $2 $3 \" \" $4}'"))

if SYS.call("pidof vlmcsd >/dev/null") == 0 then
	Status = "<b><font color=\"green\">" .. translate("KMS server is on") .. "</font></b>"
else
	Status = "<b><font color=\"red\">" .. translate("KMS server is off") .. "</font></b>"
end

m = Map("vlmcsd")
m.title	= translate("KMS Server")
m.description = translate("Version: ") .. ver .. "<br /> " .. Status
m.redirect = luci.dispatcher.build_url("admin","services","vlmcsd")

s = m:section(TypedSection, "vlmcsd")
s.anonymous=true

--基本设置
s:tab("basic", translate("Basic Settings"))

o = s:taboption("basic", Flag, "enable")
o.title = translate("enable")
o.rmempty = false

o = s:taboption("basic", Flag, "use_conf_file")
o.title = translate("Use config file")
o.rmempty = false

o = s:taboption("basic", ListValue, "ato_act", translate("Auto activate"),
	"<a href=\"http://www.right.com.cn/forum/thread-174651-1-1.html\">" ..
	translate("Reference tutorial") ..
	"</a>")
o:value("disable")
o:value("enable")

o = s:taboption("basic", Value, "port")
o.title = translate("Local Port")
o.datatype = "port"
o.default = 1688
o.placeholder = 1688
o.rmempty = false

--配置
s:tab("config", translate("config"))

local file = "/etc/vlmcsd.ini"
o = s:taboption("config", TextValue, "configfile")
o.description = translate("Each line of the beginning of the numeric sign (#) or semicolon (;) is treated as a comment, removing the semicolon (;) to enable the option.")
o.rows = 20
o.wrap = "off"
o.cfgvalue = function(self, section)
	return NXFS.readfile(file) or ""
end
o.write = function(self, section, value)
	NXFS.writefile(file, value:gsub("\r\n", "\n"))
end

--日志
s:tab("log",translate("Log"))
local logfile = "/var/log/vlmcsd.log"
l = s:taboption("log", TextValue, "logfile")
l.rows = 20
l.wrap = "off"
l.cfgvalue = function(self, section)
	return NXFS.readfile(logfile) or ""
end

return m
