#
# Copyright (C) 2006-2009 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=elinks
PKG_VERSION:=0.18.0
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=f7a93b46373b9055c8f331aaa952e58c802b8a2c
PKG_SOURCE_URL:=https://github.com/rkd77/elinks
PKG_MIRROR_HASH:=051ed1f72b2a418a7924dbcdebfe382722b408043f5502d505e57a5e7f8f6a45

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/nls.mk
include $(INCLUDE_DIR)/meson.mk

define Package/elinks
  SECTION:=net
  CATEGORY:=Network
  TITLE:=A text based web browser
  URL:=http://elinks.or.cz/
  DEPENDS:=+ca-bundle +libexpat +libidn2 +libncursesw +libopenssl +zlib $(ICONV_DEPENDS)
endef

define Package/elinks/description
 An advanced text based web browser.
endef

MESON_ARGS += \
	-Dapidoc=false \
	-Dbacktrace=false \
	-Ddoc=false \
	-Dftp=false \
	-Dgettext=true \
	-Dgpm=false \
	-Dhtmldoc=false \
	-Dlibcss=false \
	-Dlibcurl=false \
	-Dpdfdoc=false \
	-Dsftp=false \
	-Dsmall=true \
	-Dterminfo=true \
	-Dtre=false

TARGET_LDFLAGS += $(if $(ICONV_FULL),-liconv) $(if $(INTL_FULL),-lintl)

define Package/elinks/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/opt/bin/elinks $(1)/opt/bin
endef

$(eval $(call BuildPackage,elinks))
