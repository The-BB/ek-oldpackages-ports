#
# Copyright (C) 2006-2009 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# Abandoned in 2007

include $(TOPDIR)/rules.mk

PKG_NAME:=ipcad
PKG_VERSION:=3.7.3
PKG_RELEASE:=3

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=@SF/ipcad
PKG_HASH:=72372d46ae35e4d7cc74d96fbaf8bb0ae189aa9ecfd89026487aca790c2f0716

PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/ipcad
  SECTION:=net
  CATEGORY:=Network
  DEPENDS:=+libpcap
  TITLE:=listens for traffic on the specified interfaces
  URL:=http://lionet.info/ipcad/
endef

define Package/ipcad/description
	This daemon listens for traffic on the specified interfaces.
	It has the built-in RSH and NetFlow engines to allow exporting
	the accounting data the same way as Cisco routers do.
endef

define Package/ipcad/conffiles/
/opt/etc/ipcad.conf
endef

CONFIGURE_ARGS += \
	--enable-shared \
	--disable-static \
	--with-psrc=pcap \
	--with-pcap-include="$(STAGING_DIR)/opt/include" \
	--with-pcap-libraries="$(STAGING_DIR)/opt/lib"

# XXX: don't detect/use netfilter QUEUE/ULOG captures
CONFIGURE_VARS += \
	ac_cv_func_getifaddrs=no \
	ac_cv_header_ifaddrs_h=no \
	ac_cv_header_linux_netfilter_ipv4_ip_queue_h=no \
	ac_cv_header_linux_netfilter_ipv4_ipt_ULOG_h=no

define Package/ipcad/install
	$(INSTALL_DIR) $(1)/opt/etc
	$(CP) $(PKG_INSTALL_DIR)/opt/etc/ipcad.conf $(1)/opt/etc/
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/opt/bin/ipcad $(1)/opt/bin/
endef

$(eval $(call BuildPackage,ipcad))
