# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# Abandoned in 2008

include $(TOPDIR)/rules.mk

PKG_NAME:=curlftpfs
PKG_VERSION:=0.9.2
PKG_RELEASE:=3

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=@SF/curlftpfs
PKG_HASH:=4eb44739c7078ba0edde177bdd266c4cfb7c621075f47f64c85a06b12b3c6958

PKG_BUILD_DEPENDS:=libiconv-full
PKG_FIXUP:=autoreconf

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/nls.mk

define Package/curlftpfs
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Filesystem
  DEPENDS:=+libcurl +libfuse +glib2
  TITLE:=CurlFtpFS
  URL:=http://curlftpfs.sourceforge.net/
endef

define Package/curlftpfs/description
  CurlFtpFS is a filesystem for accessing FTP hosts
  based on FUSE and libcurl.
endef

TARGET_CFLAGS += \
	-I$(STAGING_DIR)/opt/include/fuse \
	-pthread

define Package/curlftpfs/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/curlftpfs $(1)/opt/bin/
endef

$(eval $(call BuildPackage,curlftpfs))

