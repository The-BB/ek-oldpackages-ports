#
# Copyright (C) 2006-2011 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# ARMv5 support is dropped in current versions:
# https://github.com/nodejs/node/issues/3061#issuecomment-143308732

include $(TOPDIR)/rules.mk

PKG_NAME:=node-legacy
PKG_VERSION:=v0.10.48
PKG_RELEASE:=2

PKG_SOURCE:=node-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=http://nodejs.org/dist/$(PKG_VERSION)
PKG_HASH:=27a1765b86bf4ec9833e2f89e8421ba4bc01a326b883f125de2f0b3494bd5549

PKG_INSTALL:=1
PKG_BUILD_FLAGS:=no-mips16
PKG_BUILD_DIR:=$(BUILD_DIR)/node-$(PKG_VERSION)

PKG_MAINTAINER:=John Crispin <blogic@openwrt.org>
PKG_LICENSE:=
PKG_BUILD_PARALLEL:=0

include $(INCLUDE_DIR)/package.mk

define Package/node-legacy
  SECTION:=lang
  CATEGORY:=Languages
  SUBMENU:=Node.js
  TITLE:=Node.js is a platform built on Chrome's JavaScript runtime
  URL:=http://nodejs.org/
  DEPENDS:=+libstdcpp +libuv +zlib +ca-certificates @arm
  PROVIDES:=node_legacy
endef

define Package/node-legacy/description
  Node.js is a JavaScript runtime built on Chrome's V8 JavaScript engine. Node.js uses
  an event-driven, non-blocking I/O model that makes it lightweight and efficient. Node.js'
   package ecosystem, npm, is the largest ecosystem of open source libraries in the world.
endef

MAKE_VARS += \
	DESTCPU=$(CPU)

CONFIGURE_ARGS= \
	--dest-cpu=$(CPU) \
	--dest-os=linux \
	--without-snapshot \
	--shared-zlib \
	--prefix=/opt \
	--with-arm-float-abi=softfp \
	--with-mips-float-abi=soft

TARGET_CXXFLAGS+= -fpermissive

define Build/InstallDev
	$(INSTALL_DIR) $(1)/opt/include
	$(CP) $(PKG_INSTALL_DIR)/opt/include/* $(1)/opt/include
endef

define Package/node-legacy/install
	mkdir -p $(1)/opt/bin $(1)/opt/lib/node_modules/npm/{bin,lib,node_modules}
	$(CP) $(PKG_INSTALL_DIR)/opt/bin/{node,npm} $(1)/opt/bin
	$(CP) $(PKG_INSTALL_DIR)/opt/lib/node_modules/npm/{package.json,LICENSE,cli.js} $(1)/opt/lib/node_modules/npm
	$(CP) $(PKG_INSTALL_DIR)/opt/lib/node_modules/npm/bin/npm-cli.js $(1)/opt/lib/node_modules/npm/bin
	$(CP) $(PKG_INSTALL_DIR)/opt/lib/node_modules/npm/lib/* $(1)/opt/lib/node_modules/npm/lib
	$(CP) $(PKG_INSTALL_DIR)/opt/lib/node_modules/npm/node_modules/* $(1)/opt/lib/node_modules/npm/node_modules
endef

$(eval $(call BuildPackage,node-legacy))
