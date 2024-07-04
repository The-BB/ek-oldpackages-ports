#
# Copyright (C) 2007-2010 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# Abandoned in 2015

include $(TOPDIR)/rules.mk

PKG_NAME:=streamripper
PKG_RELEASE:=2

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/streamripper/streamripper.git
PKG_SOURCE_DATE:=2015-08-04
PKG_SOURCE_VERSION:=248f771250998e38a2d8212aa43ccc4a516f853b
PKG_MIRROR_HASH:=6f074c4a5ad6c05904117811c8db6ee5ddace7608e1220d08680d15d0a4b67b4

PKG_VERSION:=1.65.0_git$(subst -,,$(PKG_SOURCE_DATE))~$(call version_abbrev,$(PKG_SOURCE_VERSION))

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk
include $(INCLUDE_DIR)/nls.mk

define Package/streamripper
	SECTION:=multimedia
	CATEGORY:=Multimedia
	DEPENDS:=+libmad +libvorbis +glib2
	TITLE:=streamripper
	URL:=https://github.com/streamripper/streamripper
endef

define Package/streamripper/description
 Streamripper is an Open Source application that lets you record streaming
 mp3 to your hard drive.
endef

TARGET_CFLAGS += -pthread -I$(STAGING_DIR)/opt/include

define Package/streamripper/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/opt/bin/streamripper $(1)/opt/bin
endef

$(eval $(call BuildPackage,streamripper))
