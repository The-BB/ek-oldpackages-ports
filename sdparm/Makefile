#
# Copyright (C) 2007-2008 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=sdparm
PKG_VERSION:=1.12
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tgz
PKG_SOURCE_URL:=https://sg.danny.cz/sg/p
PKG_HASH:=e7f84247069da9a0c293963948d8aba8e5897a13e35e5476c8258acb7ca3a124

PKG_LICENSE:=BSD-2-Clouse
PKG_LICENSE_FILES:=BSD_LICENSE

PKG_FIXUP:=autoreconf

include $(INCLUDE_DIR)/package.mk

define Package/sdparm
  SECTION:=utils
  CATEGORY:=Utilities
  SUBMENU:=Disc
  TITLE:=List or change SCSI disk parameters
  URL:=https://sg.danny.cz/sg/sdparm.html
endef

define Package/sdparm/description
SCSI disk parameters are held in mode pages. This utility lists or
changes those parameters. Other SCSI devices (or devices that use
the SCSI command set) such as CD/DVD and tape drives may also find
parts of sdparm useful. Requires the linux kernel 2.4 series or later.
In the 2.6 series (or later) any device node the understands a SCSI
command set may be used (e.g. /dev/sda).

Fetches Vital Product Data (VPD) pages. Can send commands to start
or stop the media and load or unload removable media.

Warning: It is possible (but unlikely) to change SCSI disk settings
such that the disk stops operating or is slowed down. Use with care.
endef

define Package/sdparm/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/sdparm $(1)/opt/bin
endef

$(eval $(call BuildPackage,sdparm))
