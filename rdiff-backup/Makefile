#
# Copyright (C) 2006-2009 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=rdiff-backup
PKG_VERSION:=2.2.6
PKG_RELEASE:=2

PYPI_NAME:=rdiff-backup
PKG_HASH:=d0778357266bc6513bb7f75a4570b29b24b2760348bbf607babfc3a6f09458cf

PKG_LICENSE:=GPL-2.0-or-later
PKG_LICENSE_FILES:=COPYING

PKG_BUILD_DEPENDS:=python-setuptools-scm/host

include $(TOPDIR)/feeds/packages/lang/python/pypi.mk
include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/python/python3-package.mk

define Package/python3-rdiff-backup
  SUBMENU:=Backup
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=Incremental backup utility
  URL:=https://rdiff-backup.net/
  DEPENDS:=+librsync +python3-urllib +python3-yaml
endef

define Package/python3-rdiff-backup/description
  rdiff-backup backs up one directory to another, possibly over a
  network. The target directory ends up a copy of the source directory,
  but extra reverse diffs are stored in a special subdirectory of that
  target directory, so you can still recover files lost some time ago.
  The idea is to combine the best features of a mirror and an incremental
  backup.
endef

define Package/python3-rdiff-backup/postrm
#!/bin/sh

rm -rf $(PYTHON3_PKG_DIR)/$(PYPI_NAME)
rm -rf $(PYTHON3_PKG_DIR)/$(PYPI_NAME)-$(PKG_VERSION).dist-info
rm -rf $(PYTHON3_PKG_DIR)/rdiffbackup
endef

$(eval $(call Py3Package,python3-rdiff-backup))
$(eval $(call BuildPackage,python3-rdiff-backup))
