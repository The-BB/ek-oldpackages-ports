#
# Copyright (C) 2006-2011 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# Abandoned in 2015

include $(TOPDIR)/rules.mk

PKG_NAME:=unfs3
PKG_VERSION=0.9.23
PKG_RELEASE:=2

PKG_SOURCE_PROTO:=git
PKG_SOURCE_DATE:=2015-05-11
PKG_SOURCE_VERSION:=5aa8be4012b552b0633b3cbdcd016104a0290167
PKG_SOURCE_URL:=https://github.com/allspace/eunfs3.git
PKG_MIRROR_HASH:=3b1c80dd398a0b3bcfd74901d99ea86f68f20faa7de23c3f31a1e8ae5879136c

PKG_VERSION:=$(PKG_VERSION)_git$(subst -,,$(PKG_SOURCE_DATE))~$(call version_abbrev,$(PKG_SOURCE_VERSION))

PKG_FIXUP:=autoreconf
PKG_BUILD_PARALLEL:=0

include $(INCLUDE_DIR)/package.mk

define Package/unfs3
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Filesystem
  DEPENDS:=+rpcbind +libacl +libtirpc
  TITLE:=User-space NFSv3 Server
  URL:=http://unfs3.sourceforge.net/
endef

define Package/unfs3/description
	UNFS3 is a user-space implementation of the NFSv3 server
	specification. It provides a daemon for the MOUNT and NFS
	protocols, which are used by NFS clients for accessing files
	on the server.
endef

# error: 'off64_t' undeclared (first use in this function); did you mean 'off_t'?
ifeq ($(CONFIG_USE_MUSL),y)
TARGET_CFLAGS += -D_LARGEFILE64_SOURCE
endif

TARGET_CPPFLAGS += -I$(STAGING_DIR)/opt/include/tirpc
TARGET_LDFLAGS += -L$(STAGING_DIR)/opt/lib -ltirpc

CONFIGURE_ARGS += \
	--without-afp-prefix \
	CFLAGS="$(TARGET_CFLAGS) $(TARGET_CPPFLAGS)"

define Package/unfs3/install
	$(INSTALL_DIR) $(1)/opt/etc/init.d
	$(INSTALL_BIN) ./files/S56unfsd $(1)/opt/etc/init.d
	$(INSTALL_DATA) ./files/$(PKG_NAME).exports $(1)/opt/etc/exports
	$(INSTALL_DIR) $(1)/opt/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/unfsd $(1)/opt/sbin
endef

define Package/unfs3/conffiles
/opt/etc/exports
endef

$(eval $(call BuildPackage,unfs3))
