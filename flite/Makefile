#
# Copyright (C) 2006-2010 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=flite
PKG_VERSION:=2.2
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=e9e2e37c329dbe98bfeb27a1828ef9a71fa84f88
PKG_SOURCE_URL:=https://github.com/festvox/flite
PKG_MIRROR_HASH:=ecf4ce3fd725948baaf3c7e71cc56dd713c44625c9684f6adb6425b93af21a11

PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/flite
	SECTION:=sound
	CATEGORY:=Sound
	DEPENDS:=+alsa-lib
	TITLE:=Text-to-speech for embedded systems
	URL:=http://www.speech.cs.cmu.edu/flite/index.html
endef

define Package/flite/description
 Festival Lite is a stripped down version of Festival,
 the well-developed text-to-speech program written in C++.
 This program is written in C to keep memory usage low.
endef

CONFIGURE_ARGS += \
	--enable-shared \
	--with-audio="alsa" \
	--with-vox="cmu_us_kal16"

define Package/flite/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(CP) $(PKG_INSTALL_DIR)/opt/bin/flite* $(1)/opt/bin
	$(INSTALL_DIR) $(1)/opt/lib
	$(CP) $(PKG_INSTALL_DIR)/opt/lib/libflite*.so* $(1)/opt/lib
endef

$(eval $(call BuildPackage,flite))
