#!/bin/sh
uci batch <<-EOF
	set luci.main.lang=zh_cn
	set luci.languages.zh_cn=ÆÕÍ¨»° (Chinese)
	set system.@system[0].zonename=Asia/Shanghai
	commit system
	commit luci
EOF
