#
# Copyright (C) 2006-2009 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# This package was orphaned in OpenWRT trunk, r32110
# Abandoned in 2013

include $(TOPDIR)/rules.mk

PKG_NAME:=palantir
PKG_VERSION:=2.8_pre3
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-server-20130906.tgz
PKG_SOURCE_URL:=http://www.fastpath.it/products/palantir/pub/
PKG_HASH:=ab7890d589be2e5c50405405361de520a9b14b7924d74e31c84e4f5cb3ee0130

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-server-20130906

include $(INCLUDE_DIR)/package.mk

define Package/palantir
	SECTION:=multimedia
	CATEGORY:=Multimedia
	DEPENDS:=+libjpeg +libpthread
	TITLE:=A multichannel interactive streaming solution
	URL:=http://www.fastpath.it/products/palantir/
endef

define Package/palantir/description
	Palantir is a Linux-based streaming system designed to transmit live
	video, audio and data over a TCP/IP network, as well as to control
	remote devices.
endef

define Package/palantir/conffiles
/opt/etc/palantir.conf
endef

export CPPFLAGS=$(TARGET_CPPFLAGS)
export LDFLAGS=$(TARGET_LDFLAGS)

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR)/server/libgsm \
		$(TARGET_CONFIGURE_OPTS) \
		CCINC="$(TARGET_CPPFLAGS)" \
		COPTS="$(TARGET_CFLAGS)" \
		lib/libgsm.a
	$(MAKE) -C $(PKG_BUILD_DIR)/server \
		$(TARGET_CONFIGURE_OPTS) \
		COPTS="$(TARGET_CFLAGS)" \
		palantir
endef

define Package/palantir/install
	$(INSTALL_DIR) $(1)/opt/etc
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/server/palantir-mips.conf.sample $(1)/opt/etc/palantir.conf
	$(INSTALL_DIR) $(1)/opt/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/server/palantir $(1)/opt/sbin/
endef

$(eval $(call BuildPackage,palantir))
