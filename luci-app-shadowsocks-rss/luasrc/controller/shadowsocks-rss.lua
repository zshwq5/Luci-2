module("luci.controller.shadowsocks-rss", package.seeall)
function index()
		if not nixio.fs.access("/etc/config/shadowsocksr") then
		return
	end
	entry({"admin", "services", "shadowsocksr"}, cbi("shadowsocks-rss/shadowsocksr"), _("ShadowsocksR")).dependent = true
	entry({"admin", "services", "shadowsocksr", "serverconfig"}, cbi("shadowsocks-rss/serverconfig"), nil ).leaf = true
end
