#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=remind
PKG_VERSION:=05.03.05
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://dianne.skoll.ca/projects/remind/download
PKG_HASH:=2f6b7fa45634c0bc8fa8d28f712b729f9176056074f43ca4dd5abce6b4c0255a

PKG_LICENSE:=GPL-2.0-only
PKG_LICENSE_FILES:=COPYRIGHT

include $(INCLUDE_DIR)/package.mk

define Package/remind
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=a sophisticated calendar and alarm program
  URL:=https://dianne.skoll.ca/projects/remind
  DEPENDS:=+perl-json-maybexs
endef

define Package/remind/description
 Remind is an advanced calendar/reminder program for UNIX and Linux.
endef

CONFIGURE_VARS += \
	PERL=$(STAGING_DIR_HOSTPKG)/usr/bin/perl

define Package/remind/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/{remind,rem2ps} $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/rem2html/rem2html $(1)/opt/bin
endef

$(eval $(call BuildPackage,remind))
