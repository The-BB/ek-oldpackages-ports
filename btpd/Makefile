#
# Copyright (C) 2009-2011 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=btpd
PKG_REAL_VERSION:=0.16
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_DATE:=2020-04-07
PKG_SOURCE_VERSION:=a3a10dfe1ece4a726530353a7b208c0cb4ff7e0d
PKG_SOURCE_URL:=https://github.com/btpd/btpd
PKG_MIRROR_HASH:=1a8c92d898dc9781ac0030ea5db730642925784e322a9d4254e3078daaee8dff

PKG_VERSION:=$(PKG_REAL_VERSION)_git$(subst -,,$(PKG_SOURCE_DATE))~$(call version_abbrev,$(PKG_SOURCE_VERSION))

PKG_LICENSE:=BSD-2-Clause BSD-3-Clause
PKG_LICENSE_FILES:=LICENSE

PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/btpd
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=BitTorrent
  TITLE:=BitTorrent Protocol Daemon
  URL:=https://github.com/btpd/btpd/wiki/
endef

define Package/btpd/description
  BTPD is a bittorrent client consisting of a daemon and client commands,
  which can be used to read and/or manipulate the daemon state. The daemon
  is capable of running several torrents simultaneously and only uses one
  TCP port. It's fairly low on resource usage and should be perfect for
  file distribution sites. Efficient downloads and ease of use makes this
  client a good choice for the casual user as well.
endef

define Package/btpd/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/opt/bin/bt{cli,info,pd} $(1)/opt/bin/
	$(INSTALL_DIR) $(1)/opt/etc/init.d
	$(INSTALL_BIN) ./files/S93btpd $(1)/opt/etc/init.d
endef

$(eval $(call BuildPackage,btpd))
