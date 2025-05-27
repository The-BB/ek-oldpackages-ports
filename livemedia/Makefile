#
# Copyright (C) 2011 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=livemedia
PKG_VERSION:=2025.05.08
PKG_RELEASE:=1

PKG_SOURCE:=live.$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=http://www.live555.com/liveMedia/public \
		https://download.videolan.org/pub/contrib/live555
PKG_HASH:=52f6ad40580c00693dbc382e0e7e2aabc1b1bb0d6dcf1fc45f7d491fdcd023ef

PKG_LICENSE:=GPL-3.0-or-later LGPL-3.0-or-later
PKG_LICENSE_FILES:=COPYING COPYING.LESSER

PKG_INSTALL:=1

PKG_BUILD_DEPENDS:=openssl

include $(INCLUDE_DIR)/package.mk

PKG_UNPACK += --strip-components=1 -C $(PKG_BUILD_DIR)

define Package/livemedia/Default
  SECTION:=multimedia
  CATEGORY:=Multimedia
  TITLE:=LIVE555 Streaming Media
  URL:=http://www.live555.com/
  DEPENDS:=+libstdcpp
endef

define Package/liblive555
$(call Package/livemedia/Default)
  SECTION:=libs
  CATEGORY:=Libraries
  TITLE+= (multimedia RTSP streaming library)
endef

define Package/live555mediaserver
$(call Package/livemedia/Default)
  TITLE+= (live555MediaServer)
  DEPENDS:=+liblive555
endef

define Package/live555proxyserver
$(call Package/livemedia/Default)
  TITLE+= (live555ProxyServer)
  DEPENDS:=+liblive555
endef

define Package/openrtsp
$(call Package/livemedia/Default)
  TITLE+= (openRTSP)
  DEPENDS:=+liblive555
endef

define Package/playsip
$(call Package/livemedia/Default)
  TITLE+= (playSIP)
  DEPENDS:=+liblive555
endef

define Package/vobstreamer
$(call Package/livemedia/Default)
  TITLE+= (vobStreamer)
  DEPENDS:=+liblive555
endef

TARGET_CFLAGS += -DNO_OPENSSL=1 -DNO_STD_LIB

define Build/Prepare
	$(PKG_UNPACK)
	chmod -R u+w $(PKG_BUILD_DIR)
	$(Build/Patch)
endef

define Build/Configure
	$(FIND) $(PKG_BUILD_DIR) -name "Makefile.*" -exec \
		$(SED) 's|PREFIX =.*$$$$|PREFIX = /opt|g' {} \;
	$(SED) 's|@CROSS_COMPILE@|$(TARGET_CROSS)|g;  \
		s|@CFLAGS@|$(TARGET_CFLAGS)|g' $(PKG_BUILD_DIR)/config.Entware
	( cd $(PKG_BUILD_DIR); ./genMakefiles Entware; )
endef

define Package/liblive555/install
	$(INSTALL_DIR) $(1)/opt/lib
	$(CP) $(PKG_INSTALL_DIR)/opt/lib/lib*.so.* $(1)/opt/lib
endef

define Package/live555mediaserver/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/opt/bin/live555MediaServer $(1)/opt/bin
endef

define Package/live555proxyserver/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/opt/bin/live555ProxyServer $(1)/opt/bin
endef

define Package/openrtsp/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/opt/bin/openRTSP $(1)/opt/bin
endef

define Package/playsip/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/opt/bin/playSIP $(1)/opt/bin
endef

define Package/vobstreamer/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/opt/bin/vobStreamer $(1)/opt/bin
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/opt/include
	$(CP) $(PKG_INSTALL_DIR)/opt/include/* $(1)/opt/include
	$(INSTALL_DIR) $(1)/opt/lib
	$(CP) $(PKG_INSTALL_DIR)/opt/lib/lib*.so* $(1)/opt/lib
	$(INSTALL_DIR) $(1)/opt/lib/pkgconfig
	$(CP) $(PKG_INSTALL_DIR)/opt/lib/pkgconfig/live555.pc $(1)/opt/lib/pkgconfig
endef

$(eval $(call BuildPackage,liblive555))
$(eval $(call BuildPackage,live555mediaserver))
$(eval $(call BuildPackage,live555proxyserver))
$(eval $(call BuildPackage,openrtsp))
$(eval $(call BuildPackage,playsip))
$(eval $(call BuildPackage,vobstreamer))
