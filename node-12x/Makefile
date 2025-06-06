#
# Copyright (C) 2006-2017 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# XXX for mips BE only

include $(TOPDIR)/rules.mk

PKG_NAME:=node
PKG_VERSION:=12.22.12
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-v$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://nodejs.org/dist/v$(PKG_VERSION)
PKG_HASH:=1a5c52c50185f7c23318e7e8001cc58054736acb98cb8c523d33b136da9e54be

PKG_MAINTAINER:=Hirokazu MORIKAWA <morikw2@gmail.com>, Adrian Panella <ianchi74@outlook.com>
PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE
PKG_CPE_ID:=cpe:/a:nodejs:node.js

#HOST_BUILD_DEPENDS:=python3/host
#HOST_BUILD_PARALLEL:=1

PKG_BUILD_DEPENDS:=python3/host
PKG_BUILD_PARALLEL:=1
PKG_INSTALL:=1
PKG_BUILD_FLAGS:=no-mips16
PKG_ASLR_PIE:=0

#include $(INCLUDE_DIR)/host-build.mk
include $(INCLUDE_DIR)/package.mk

#HOST_UNPACK += --strip-components=1 -C $(HOST_BUILD_DIR)
PKG_UNPACK += --strip-components=1 -C $(PKG_BUILD_DIR)

define Package/node-12x
  SECTION:=lang
  CATEGORY:=Languages
  SUBMENU:=Node.js
  TITLE:=Node.js is a platform built on Chrome's JavaScript runtime
  URL:=https://nodejs.org/
  DEPENDS:=@mips \
	   +libstdcpp +libopenssl +zlib +libnghttp2 +libuv \
	   +libcares +libatomic +NODEJS_12x_ICU_SYSTEM:icu +NODEJS_12x_ICU_SYSTEM:icu-full-data
ifdef CONFIG_mips
  PROVIDES:=node node-npm
endif
endef

define Package/node-12x/description
  Node.js® is a JavaScript runtime built on Chrome's V8 JavaScript engine. Node.js uses
  an event-driven, non-blocking I/O model that makes it lightweight and efficient. Node.js'
   package ecosystem, npm, is the largest ecosystem of open source libraries in the world.
  *** The following preparations must be made on the host side. ***
      1. gcc 6.3 or higher is required.
      2. To build a 32-bit target, gcc-multilib, g++-multilib are required.
      3. Requires libatomic package. (If necessary, install the 32-bit library at the same time.)
     ex) sudo apt-get install gcc-multilib g++-multilib
endef

#define Package/node-12x-npm
#  SECTION:=lang
#  CATEGORY:=Languages
#  SUBMENU:=Node.js
#  TITLE:=NPM stands for Node Package Manager
#  URL:=https://www.npmjs.com/
#  DEPENDS:=+node-12x
#  PROVIDES:= node-npm
#endef

#define Package/node-12x-npm/description
#	NPM is the package manager for NodeJS
#endef

define Package/node-12x/config
	if PACKAGE_node-12x
	choice
		prompt "i18n features"
		default NODEJS_12x_ICU_NONE
		help
		 Select i18n features

		config NODEJS_12x_ICU_NONE
			bool "Disable"

		config NODEJS_12x_ICU_SMALL
			bool "small-icu"

		config NODEJS_12x_ICU_SYSTEM
			depends on ARCH_64BIT
			bool "system-icu"
	endchoice
	endif
endef

NODEJS_CPU:=$(subst aarch64,arm64,$(subst x86_64,x64,$(subst i386,ia32,$(ARCH))))

ifneq ($(CONFIG_ARCH_64BIT),y)
FORCE_32BIT:=-m32
endif

# XXX OpenSSL 3.x
TARGET_CXXFLAGS += -fpermissive

MAKE_VARS+= \
	DESTCPU=$(NODEJS_CPU) \
	NO_LOAD='cctest.target.mk embedtest.target.mk node_mksnapshot.target.mk' \
	LD_LIBRARY_PATH=$(STAGING_DIR_HOSTPKG)/share/icu/current/lib

#HOST_MAKE_VARS+=NO_LOAD='cctest.target.mk embedtest.target.mk'

CONFIGURE_VARS:= \
	CC="$(TARGET_CC) $(TARGET_OPTIMIZATION)" \
	CXX="$(TARGET_CXX) $(TARGET_OPTIMIZATION)" \
	CC_host="$(HOSTCC) $(FORCE_32BIT)" \
	CXX_host="$(HOSTCXX) $(FORCE_32BIT)"

CONFIGURE_ARGS:= \
	--dest-cpu=$(NODEJS_CPU) \
	--dest-os=linux \
	--cross-compiling \
	--shared-zlib \
	--shared-openssl \
	--shared-nghttp2 \
	--shared-libuv \
	--shared-cares \
	--with-intl=$(if $(CONFIG_NODEJS_12x_ICU_SMALL),small-icu,$(if $(CONFIG_NODEJS_12x_ICU_SYSTEM),system-icu,none)) \
	$(if $(findstring mips,$(NODEJS_CPU)), \
		$(if $(CONFIG_SOFT_FLOAT),--with-mips-float-abi=soft)) \
	$(if $(findstring +neon,$(CONFIG_CPU_TYPE)),--with-arm-fpu=neon) \
	$(if $(findstring +vfp",$(CONFIG_CPU_TYPE)),--with-arm-fpu=vfp) \
	$(if $(findstring +vfpv3",$(CONFIG_CPU_TYPE)),--with-arm-fpu=vfpv3-d16) \
	$(if $(findstring +vfpv4",$(CONFIG_CPU_TYPE)),--with-arm-fpu=vfpv3) \
	--prefix=/opt

#HOST_CONFIGURE_VARS:=

#HOST_CONFIGURE_ARGS:= \
#	--dest-os=$(if $(findstring Darwin,$(HOST_OS)),mac,linux) \
#	--with-intl=small-icu \
#	--prefix=$(STAGING_DIR_HOSTPKG)

define Build/InstallDev
	$(INSTALL_DIR) $(1)/opt/include
	$(CP) $(PKG_INSTALL_DIR)/opt/include/* $(1)/opt/include/
endef

define Package/node-12x/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/opt/bin/node $(1)/opt/bin/
#endef

#define Package/node-12x-npm/install
	$(INSTALL_DIR) $(1)/opt/lib/node_modules
	$(CP) $(PKG_INSTALL_DIR)/opt/lib/node_modules/* $(1)/opt/lib/node_modules/
	$(INSTALL_DIR) $(1)/opt/bin
	$(LN) ../lib/node_modules/npm/bin/npm-cli.js $(1)/opt/bin/npm
	$(LN) ../lib/node_modules/npm/bin/npx-cli.js $(1)/opt/bin/npx
	# Entware specific: fix exec path in scripts
	$(FIND) $(1)/opt/lib/node_modules -type f -exec $(SED) \
		's,^#!.*node,#!/opt/bin/node,; \
		s,^#!.*python,#!/opt/bin/python,; \
		s,^#!.*bash,#!/opt/bin/bash,; \
		s,^#!.*env sh,#!/bin/sh,' {} +
endef

#$(eval $(call HostBuild))
$(eval $(call BuildPackage,node-12x))
#$(eval $(call BuildPackage,node-npm))
