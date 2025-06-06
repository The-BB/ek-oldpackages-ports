#
# Copyright (C) 2011-2020 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=gerbera
PKG_VERSION:=2.5.0
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://codeload.github.com/gerbera/gerbera/tar.gz/v$(PKG_VERSION)?
PKG_HASH:=e1dd2c710758fbb9f4db6f1afc461bdd1b6c55ef29147d450ab6d90624177f09

PKG_MAINTAINER:=
PKG_LICENSE:=GPL-2.0-or-later
PKG_LICENSE_FILES:=LICENSE.md

PKG_BUILD_DEPENDS:=libmatroska pugixml spdlog

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/gerbera
  SECTION:=multimedia
  CATEGORY:=Multimedia
  DEPENDS:=+libmagic +libupnp +libsqlite3 +libexif +libexiv2 +libuuid +libfmt +curl +duktape +libffmpegthumbnailer
  TITLE:=A free media server
  URL:=https://gerbera.io
endef

define Package/gerbera/description
 Gerbera - UPnP Media Server based on Mediatomb.
endef

define Package/gerbera/conffiles
/opt/etc/gerbera/config.xml
endef

CMAKE_OPTIONS += \
	-DWITH_MYSQL=0 \
	-DWITH_TAGLIB=0 \
	-DWITH_AVCODEC=1 \
	-DWITH_FFMPEGTHUMBNAILER=1 \
	-DWITH_SYSTEMD=0 \
	-DWITH_DEBUG=0

define Package/gerbera/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/opt/bin/gerbera $(1)/opt/bin
	$(INSTALL_DIR) $(1)/opt/share
	$(CP) $(PKG_INSTALL_DIR)/opt/share/gerbera $(1)/opt/share
	$(INSTALL_DIR) $(1)/opt/etc/init.d
	$(INSTALL_BIN) ./files/S90gerbera $(1)/opt/etc/init.d
endef

$(eval $(call BuildPackage,gerbera))
