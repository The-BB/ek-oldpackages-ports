#
# Copyright (C) 2008-2010 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# Depends on nagios 3.x only, no need to update it in future

include $(TOPDIR)/rules.mk

PKG_NAME:=nagios-plugins
PKG_VERSION:=2.0.3
PKG_RELEASE:=3

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=http://nagios-plugins.org/download
PKG_HASH:=8f0021442dce0138f0285ca22960b870662e28ae8973d49d439463588aada04a

PKG_BUILD_DEPENDS:=bind
PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/nagios-plugins
  SECTION:=admin
  CATEGORY:=Administration
  DEPENDS:=+bash +libopenssl
  TITLE:=plugins for Nagios checks
  URL:=http://nagiosplug.sourceforge.net/
endef

ifeq ($(CONFIG_GCC_USE_VERSION_14),y)
TARGET_CFLAGS += -std=gnu89
endif

CONFIGURE_ARGS += \
	--with-trusted-path="/opt/bin:/opt/sbin:/opt/usr/bin:/opt/usr/sbin" \
	--with-perl="/opt/bin/perl" \
	--with-openssl="$(STAGING_DIR)/opt" \
	--without-pgsql \
	--without-radius \
	--without-ldap \
	--without-mysql \
	--without-dbi \
	$(call autoconf_bool,CONFIG_IPV6,ipv6) \
	--with-ping-command="/opt/bin/ping -w %d -c %d %s" \
	--with-ping6-command="/opt/bin/ping6 -w %d -c %d %s" \
	--with-ps-command="/opt/bin/ps w" \
	--with-ps-cols="6" \
	--with-ps-format="%d %s %d %s %s %n" \
	--with-ps-varlist="&procpid$(comma)&procuid$(comma)&procvsz$(comma)procstat$(comma)procprog$(comma)&pos" \
	--with-uptime-command="/opt/bin/uptime" \
	--with-ssh-command="/opt/bin/ssh" \
	--with-nslookup-command="/opt/bin/nslookup" \
	--with-dig-command="/opt/bin/dig"

CONFIGURE_VARS += \
	PATH_TO_DIG='/opt/bin/dig' \
	PATH_TO_NSLOOKUP='/opt/bin/nslookup' \
	PATH_TO_PING6='/opt/bin/ping6' \
	PATH_TO_PING='/opt/bin/ping' \
	PATH_TO_PS='/opt/bin/ps' \
	PATH_TO_SSH='/opt/bin/ssh' \
	PATH_TO_UPTIME='/opt/bin/uptime' \
	$(if $(CONFIG_USE_MUSL),ac_cv_lib_bsd_pow=no)

define Package/nagios-plugins/install
	$(INSTALL_DIR) $(1)/opt/lib
	$(CP) $(PKG_INSTALL_DIR)/opt/lib/* $(1)/opt/lib
	$(SED) 's,/bin/bash,/opt/bin/bash,g' \
	    $(1)/opt/lib/check_{log,oracle,sensors}
	$(SED) 's,$(STAGING_DIR_HOST),/opt,' \
	    $(1)/opt/lib/check_log
endef

$(eval $(call BuildPackage,nagios-plugins))
