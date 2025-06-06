#
# Copyright (C) 2007-2010 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=rsnapshot
PKG_VERSION:=1.5.1
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://codeload.github.com/rsnapshot/rsnapshot/tar.gz/refs/tags/$(PKG_VERSION)?
PKG_HASH:=88d2b53d0807d6c7f9a803fc19f5a64fcb028d9dad6a880ca9941a1d5e730742

PKG_LICENSE:=GPL-2.0-only
PKG_LICENSE_FILES:=COPYING

PKG_INSTALL:=1
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk

define Package/rsnapshot
  SUBMENU:=Backup
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=rsnapshot Backup
  URL:=https://rsnapshot.org/
  DEPENDS:=+rsync +perl \
		+perlbase-autoloader \
		+perlbase-class \
		+perlbase-cwd \
		+perlbase-dirhandle \
		+perlbase-essential \
		+perlbase-fcntl \
		+perlbase-file \
		+perlbase-getopt \
		+perlbase-io \
		+perlbase-ipc \
		+perlbase-posix \
		+perlbase-selectsaver \
		+perlbase-tie \
		+perlbase-xsloader \
		+coreutils-cp \
		+coreutils-du \
		+coreutils-rm
endef

define Package/rsnapshot/description
  rsnapshot is a filesystem snapshot utility for making backups of local and
  remote systems.

  Using rsync and hard links, it is possible to keep multiple, full backups
  instantly available. The disk space required is just a little more than the
  space of one full backup, plus incrementals.
endef

define Package/rsnapshot/conffiles
/opt/etc/$(PKG_NAME).conf
endef

CONFIGURE_ARGS += \
	--without-logger

CONFIGURE_VARS += \
	ac_cv_path_PERL=/opt/bin/perl \
	ac_cv_path_RSYNC=/opt/bin/rsync \
	ac_cv_path_CP=/opt/bin/cp \
	ac_cv_path_RM=/opt/bin/rm \
	ac_cv_path_DU=/opt/bin/du \
	ac_cv_path_SSH=/opt/bin/ssh

define Build/Configure
	( cd $(PKG_BUILD_DIR); ./autogen.sh; )
	$(call Build/Configure/Default)
endef

define Package/rsnapshot/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) \
		$(PKG_INSTALL_DIR)/opt/bin/$(PKG_NAME){,-diff} \
			$(1)/opt/bin
	$(INSTALL_DIR) $(1)/opt/etc
	$(INSTALL_DATA) \
		$(PKG_INSTALL_DIR)/opt/etc/$(PKG_NAME).conf.default \
			$(1)/opt/etc/$(PKG_NAME).conf
endef

$(eval $(call BuildPackage,rsnapshot))
