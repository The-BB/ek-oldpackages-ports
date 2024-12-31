#
# Copyright (C) 2006 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# Abandoned in 2012

include $(TOPDIR)/rules.mk

PKG_NAME:=cutter
PKG_VERSION:=1.04
PKG_RELEASE:=2

include $(INCLUDE_DIR)/package.mk

define Package/cutter
  SECTION:=net
  CATEGORY:=Network
  TITLE:=allows an user to abort TCP/IP connections
  URL:=http://www.lowth.com/cutter/
endef

define Package/cutter/description
	Cutter is an open source program that allows Linux firewall
	administrators to abort TCP/IP connections routed over the
	firewall or router on which it is run.
endef

define Package/cutter/install
	$(INSTALL_DIR) $(1)/opt/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/cutter $(1)/opt/sbin/
endef

$(eval $(call BuildPackage,cutter))
