#
# Copyright (C) 2006 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# Abandoned in 2017

include $(TOPDIR)/rules.mk

PKG_NAME:=dtach
PKG_VERSION:=0.9
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=7acac922770597f5da5df7b290078770d20dac32
PKG_SOURCE_URL:=https://github.com/crigler/dtach
PKG_MIRROR_HASH:=fcb954b220ab5812b475b53374a1efbca096571e171272a29e351351cff009ce

include $(INCLUDE_DIR)/package.mk

define Package/dtach
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=A program that emulates the dtach feature of screen
  URL:=http://dtach.sourceforge.net/
endef

define Package/dtach/description
 dtach is a tiny program that emulates the detach feature of screen,
 allowing you to run a program in an environment that is protected from
 the controlling terminal and attach to it later. dtach does not keep
 track of the contents of the screen, and thus works best with programs
 that know how to redraw themselves.
endef

define Package/dtach/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/dtach $(1)/opt/bin
endef

$(eval $(call BuildPackage,dtach))
