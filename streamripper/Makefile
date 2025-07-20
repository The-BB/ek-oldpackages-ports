#
# Copyright (C) 2007-2010 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# Abandoned in 2015

include $(TOPDIR)/rules.mk

PKG_NAME:=streamripper
PKG_REAL_VERSION:=1.65.0
PKG_RELEASE:=2

PKG_SOURCE_PROTO:=git
PKG_SOURCE_DATE:=2015-08-04
PKG_SOURCE_VERSION:=248f771250998e38a2d8212aa43ccc4a516f853b
PKG_SOURCE_URL:=https://github.com/streamripper/streamripper
PKG_MIRROR_HASH:=6f074c4a5ad6c05904117811c8db6ee5ddace7608e1220d08680d15d0a4b67b4

PKG_VERSION:=$(PKG_REAL_VERSION)_git$(subst -,,$(PKG_SOURCE_DATE))~$(call version_abbrev,$(PKG_SOURCE_VERSION))

PKG_LICENSE:=GPL-2.0-only
PKG_LICENSE_FILES:=COPYING

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk
include $(INCLUDE_DIR)/nls.mk

define Package/streamripper
  SECTION:=multimedia
  CATEGORY:=Multimedia
  TITLE:=rip shoutcast radio streams to mp3 files
  URL:=https://streamripper.sourceforge.net/
  DEPENDS:=+glib2 +libmad +libvorbis
endef

define Package/streamripper/description
  Streamripper records shoutcast and icecast compatible streams, in
  their native format.
  The following formats are supported: mp3, nsv, aac, and ogg. The meta data
  within the stream are interpreted to determine the beginning and end of each
  song, and stores the songs on your hard disk as individual files. In addition,
  streamripper includes a relay server for listening to the station while you
  are recording.
endef

TARGET_CFLAGS += -pthread -I$(STAGING_DIR)/opt/include

ifeq ($(CONFIG_GCC_USE_VERSION_14),y)
TARGET_CFLAGS += -std=gnu89
endif

define Package/streamripper/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/opt/bin/streamripper $(1)/opt/bin
endef

$(eval $(call BuildPackage,streamripper))
