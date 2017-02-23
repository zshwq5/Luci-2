#!/bin/sh
uci batch <<-EOF
	set luci.main.lang=zh_cn
	set luci.main.mediaurlbase=/luci-static/material
	commit luci
EOF
