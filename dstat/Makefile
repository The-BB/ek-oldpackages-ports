#
# Copyright (C) 2012 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# Project archieved

include $(TOPDIR)/rules.mk

PKG_NAME:=dstat
PKG_VERSION:=0.7.4
PKG_RELEASE:=2

PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=6f5db0aed26bf8cf2700d4ffe90a9bd3436ac728
PKG_SOURCE_URL:=https://github.com/dagwieers/dstat
PKG_MIRROR_HASH:=f3925473b758a9df18823c76521017f46b8f234080efa2a4af7366dc98487788

PYTHON3_PKG_BUILD:=0

include $(INCLUDE_DIR)/package.mk

define Package/dstat
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=Versatile resource statistics tool
  URL:=http://dag.wieers.com/home-made/dstat/
  DEPENDS:=+python3-ncurses +python3-six
endef

define Package/dstat/description
  Dstat is a versatile replacement for vmstat, iostat, netstat
  and ifstat. Dstat overcomes some of their limitations and
  adds some extra features, more counters and flexibility.
  Dstat is handy for monitoring systems during performance
  tuning tests, benchmarks or troubleshooting.
endef

define Build/Compile
endef

define Package/dstat/install
	$(INSTALL_DIR) $(1)/opt/share/dstat
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/dstat $(1)/opt/share/dstat/dstat.py
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/plugins/dstat_*.py $(1)/opt/share/dstat/
	$(INSTALL_DIR) $(1)/opt/bin
	$(LN) -sf ../share/dstat/dstat.py $(1)/opt/bin/dstat
endef

$(eval $(call BuildPackage,dstat))
