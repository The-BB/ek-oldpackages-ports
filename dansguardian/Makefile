#
# Copyright (C) 2008-2015 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# Abandoned in 2012

include $(TOPDIR)/rules.mk

PKG_NAME:=dansguardian
PKG_VERSION:=2.12.0.3
PKG_RELEASE:=2

PKG_LICENSE:=GPL-2.0
PKG_MAINTAINER:=Luka Perkov <luka@openwrt.org>

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_URL:=@SF/dansguardian
PKG_HASH:=c74e9a32b97f9a9a056fced3da23fe48fca2bc6aa9af670afe9a53dc819414f5

PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/dansguardian
  SECTION:=net
  DEPENDS:=+libstdcpp +zlib
  CATEGORY:=Network
  SUBMENU:=Web Servers/Proxies
  TITLE:=DansGuardian
  URL:=http://dansguardian.org
endef

define Package/dansguardian/conffiles
/opt/etc/dansguardian/dansguardianf1.conf
endef

TARGET_CXXFLAGS += -std=gnu++98

CONFIGURE_ARGS += \
	--disable-pcre \
	--with-sysconfsubdir=dansguardian \
	--with-proxyuser=root \
	--with-proxygroup=root

define Package/dansguardian/install
	$(INSTALL_DIR) $(1)/opt/sbin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/opt/sbin/dansguardian $(1)/opt/sbin/
	$(INSTALL_DIR) $(1)/opt/etc
	$(CP) $(PKG_INSTALL_DIR)/opt/etc/dansguardian $(1)/opt/etc/
	$(INSTALL_CONF) ./files/dansguardianf1.conf \
		$(1)/opt/etc/dansguardian/dansguardianf1.conf
	$(INSTALL_DIR) $(1)/opt/share/dansguardian
	$(INSTALL_BIN) \
		$(PKG_INSTALL_DIR)/opt/share/dansguardian/transparent1x1.gif \
			$(1)/opt/share/dansguardian/
	$(INSTALL_BIN) \
		$(PKG_INSTALL_DIR)/opt/share/dansguardian/blockedflash.swf \
			$(1)/opt/share/dansguardian/
	$(INSTALL_DIR) $(1)/opt/share/dansguardian/languages/ukenglish
	$(CP) $(PKG_INSTALL_DIR)/opt/share/dansguardian/languages/ukenglish/* \
		$(1)/opt/share/dansguardian/languages/ukenglish/
	$(INSTALL_DIR) $(1)/opt/etc/init.d
	$(INSTALL_BIN) ./files/S24dansguardian $(1)/opt/etc/init.d
endef

$(eval $(call BuildPackage,dansguardian))
