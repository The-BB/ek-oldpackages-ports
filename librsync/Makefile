#
# Copyright (C) 2006-2010 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=librsync
PKG_VERSION:=2.3.4
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=v$(PKG_VERSION)
PKG_SOURCE_URL:=https://github.com/librsync/librsync
PKG_MIRROR_HASH:=a5acd088805e5c528c072476b1728b78d4fcf618141a6beb480e046e843dd595

PKG_LICENSE:=LGPL-2.1-only
PKG_LICENSE_FILES:=COPYING

CMAKE_INSTALL:=1

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/librsync
  SECTION:=libs
  CATEGORY:=Libraries
  TITLE:=remote delta-compression library
  URL:=https://librsync.github.io/
  DEPENDS:=+libbz2 +zlib
endef

define Package/librsync/description
  librsync implements the "rsync" algorithm, which allows remote
  differencing of binary files.  librsync computes a delta relative to a
  file's checksum, so the two files need not both be present to generate
  a delta.
endef

define Package/librsync/install
	$(INSTALL_DIR) $(1)/opt/lib
	$(CP) $(PKG_INSTALL_DIR)/opt/lib/librsync.so* $(1)/opt/lib
endef

$(eval $(call BuildPackage,librsync))
