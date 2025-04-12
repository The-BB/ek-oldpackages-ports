#
# Copyright (C) 2006-2011 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=unfs3
PKG_VERSION:=0.11.0
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_URL:=https://github.com/unfs3/unfs3
PKG_MIRROR_HASH:=be6e476f7bd12ae92772b0bd0c0295fce5d52359278b4d904a854f7838d0901b

PKG_LICENSE:=BSD-3-Clause
PKG_LICENSE_FILES:=LICENSE

PKG_FIXUP:=autoreconf

include $(INCLUDE_DIR)/package.mk

define Package/unfs3
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Filesystem
  TITLE:=User-space NFSv3 Server
  URL:=https://unfs3.github.io/
  DEPENDS:=+libacl +libtirpc +rpcbind
endef

define Package/unfs3/description
  UNFS3 is a user-space implementation of the NFS (Network File System)
  version 3 server specification. It provides a daemon that supports both
  the MOUNT and NFS protocol.
endef

define Package/unfs3/conffiles
/opt/etc/exports
endef

# error: 'off64_t' undeclared (first use in this function); did you mean 'off_t'?
ifeq ($(CONFIG_USE_MUSL),y)
TARGET_CFLAGS += -D_LARGEFILE64_SOURCE
endif

define Package/unfs3/install
	$(INSTALL_DIR) $(1)/opt/etc/init.d
	$(INSTALL_BIN) ./files/S56unfsd $(1)/opt/etc/init.d
	$(INSTALL_DATA) ./files/unfs3.exports $(1)/opt/etc/exports
	$(INSTALL_DIR) $(1)/opt/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/unfsd $(1)/opt/sbin
endef

$(eval $(call BuildPackage,unfs3))
