#
# Copyright (C) 2008-2014 The LuCI Team <luci@lists.subsignal.org>
#
# This is free software, licensed under the Apache License, Version 2.0 .
#

include $(TOPDIR)/rules.mk

LUCI_TITLE:=LuCI Support for Shadowsocksr-libev
LUCI_DEPENDS:=+ip-full +dnsmasq-full +ipset-lists +shadowsocksr-libev \
			+libc +iptables-mod-nat-extra
include ../../luci.mk

# call BuildPackage - OpenWrt buildroot signature
