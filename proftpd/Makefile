#
# Copyright (C) 2009-2014 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=proftpd
PKG_VERSION:=1.3.8
PKG_RELEASE:=2

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=ftp://ftp.proftpd.org/distrib/source
PKG_HASH:=f7139e7377a2cb059b8b9b14d76a6df5f440e3181cb15ae890d43bbcae574748

PKG_FIXUP:=autoreconf
PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/nls.mk

define Package/proftpd
  SUBMENU:=File Transfer
  SECTION:=net
  CATEGORY:=Network
  TITLE:=ProFTPD FTP server
  URL:=http://www.proftpd.org/
  MAINTAINER:=Cezary Jackiewicz <cezary@eko.one.pl>
  DEPENDS:=+libattr +libidn +libidn2 +libncursesw +libopenssl +libsodium \
	$(ICONV_DEPENDS) $(INTL_DEPENDS)
endef

define Package/proftpd/conffiles
/opt/etc/proftpd.conf
endef

MAKE_FLAGS += \
	INSTALL_USER=$(shell id -u) \
	INSTALL_GROUP=$(shell id -g)

CONFIGURE_ARGS += \
	--disable-cap \
	--disable-auth-pam \
	--disable-strip \
	--with-lastlog=/opt/var/log \
	--enable-nls \
	--enable-openssl \
	--with-modules=mod_digest:mod_sftp

define Package/proftpd/install
	$(INSTALL_DIR) $(1)/opt/etc/init.d
	$(INSTALL_CONF) $(PKG_INSTALL_DIR)/opt/etc/proftpd.conf $(1)/opt/etc
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/opt/bin/ftp{count,dctl,top,who} $(1)/opt/bin
	$(INSTALL_DIR) $(1)/opt/sbin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/opt/sbin/{ftpscrub,ftpshut,proftpd} $(1)/opt/sbin
	$(LN) proftpd $(1)/opt/sbin/in.proftpd
	$(INSTALL_BIN) ./files/S66proftpd $(1)/opt/etc/init.d
  ifeq ($(CONFIG_USE_MUSL),y)
	$(INSTALL_DIR) $(1)/opt/share/locale
  endif
endef

$(eval $(call BuildPackage,proftpd))
