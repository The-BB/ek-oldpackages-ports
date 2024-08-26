#
# Copyright (C) 2012 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# Abandoned in 2013
# Superseded by odhcpd, but odhcpd is tied to OpenWrt system libraries

include $(TOPDIR)/rules.mk

PKG_NAME:=6relayd
PKG_RELEASE=3

PKG_SOURCE_PROTO:=git
PKG_SOURCE_DATE:=2013-12-10
PKG_SOURCE_VERSION:=0381cf15e9721054f902354e9c3b9fb0201bab7f
PKG_SOURCE_URL:=https://github.com/sbyx/6relayd.git
PKG_MIRROR_HASH:=c439c1703711b50c9799e3ad034339126f3f7d835c7f44ac6b8cddc5f5501249

PKG_MAINTAINER:=Steven Barth <steven@midlink.org>

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/6relayd
  SECTION:=net
  CATEGORY:=Network
  TITLE:=DHCPv6(-PD)/RA Server & Relay
endef

define Package/6relayd/description
 6relayd is a daemon for serving and relaying IPv6 management protocols to
 configure clients and downstream routers.

 6relayd provides server services for RA, stateless DHCPv6, DHCPv6-PD and can
 be used to relay RA, DHCPv6 and NDP between routed (non-bridged) interfaces
 in case no delegated prefixes are provided by the upstream router.
endef

TARGET_CFLAGS += -Wno-stringop-truncation

ifneq ($(CONFIG_GCC_USE_VERSION_8),y)
TARGET_CFLAGS +=-Wno-error=address-of-packed-member
endif

define Package/6relayd/install
	$(INSTALL_DIR) $(1)/opt/sbin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/6relayd $(1)/opt/sbin/
endef

$(eval $(call BuildPackage,6relayd))
