#
# Copyright (C) 2006-2010 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# Abandoned since 2014

include $(TOPDIR)/rules.mk

PKG_NAME:=opendchub
PKG_VERSION:=0.8.3
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=@SF/opendchub
PKG_HASH:=98ae4e8e649bd850018c4b9330c29cc00be4d7db4652847f968634643b9bc4d1

PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/opendchub
  SUBMENU:=P2P
  SECTION:=net
  CATEGORY:=Network
  DEPENDS:=+libopenssl
  TITLE:=software for the Direct Connect network
  URL:=http://opendchub.sourceforge.net/
endef

define Package/opendchub/description
	Open DC hub is a Unix/Linux version of the hub software
	for the Direct Connect network
endef

define Package/opendchub/conffiles
/opt/etc/opendchub.conf
endef

ifneq ($(CONFIG_GCC_USE_VERSION_8),y)
TARGET_CFLAGS += -fcommon
endif

CONFIGURE_ARGS += \
	--disable-perl

define Package/opendchub/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/opt/bin/opendchub $(1)/opt/bin/
	$(INSTALL_DIR) $(1)/opt/etc/init.d
	$(INSTALL_BIN) ./files/S61opendchub $(1)/opt/etc/init.d
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/Documentation/configfiles \
		$(1)/opt/etc/opendchub.conf
endef

$(eval $(call BuildPackage,opendchub))
