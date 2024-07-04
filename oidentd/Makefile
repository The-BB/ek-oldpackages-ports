#
# Copyright (C) 2006-2011 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=oidentd
PKG_VERSION:=3.1.0
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=44030f6e4a4b00fe8bf62c3b128309bb9542c744
PKG_SOURCE_URL:=https://github.com/janikrabe/oidentd.git
PKG_MIRROR_HASH:=6394809bfa3f222e28485915030b4f9fac30c2df9ea20023ee58dc046b471b5f

PKG_FIXUP:=autoreconf
PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/oidentd
	SECTION:=net
	CATEGORY:=Network
	DEPENDS:=+libnetfilter-conntrack
	TITLE:=Identd server
	URL:=https://github.com/janikrabe/oidentd
endef

define Package/oidentd/description
 A nat aware identd server that will correctly forwared requests to clients.
endef

CONFIGURE_ARGS += \
	--disable-debug

define Package/oidentd/conffiles
/opt/etc/oidentd.conf
/opt/etc/oidentd_masq.conf
endef

define Package/oidentd/install
	$(INSTALL_DIR) $(1)/opt/sbin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/opt/sbin/oidentd $(1)/opt/sbin
	$(INSTALL_DIR) $(1)/opt/etc/init.d
	$(INSTALL_CONF) $(PKG_INSTALL_DIR)/opt/etc/oidentd*.conf $(1)/opt/etc
	$(INSTALL_BIN) ./files/S39oidentd $(1)/opt/etc/init.d
endef

$(eval $(call BuildPackage,oidentd))
