#
# Copyright (C) 2007-2010 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# Abandoned in 2017

include $(TOPDIR)/rules.mk

PKG_NAME:=ngrep
PKG_VERSION:=1.47
PKG_RELEASE:=3

PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=351ac491358f89a7860bbbe9963cb4bc7d60000f
PKG_SOURCE_URL:=https://github.com/jpr5/ngrep
PKG_MIRROR_HASH:=557472a823ad3c7eb77ed7a2a143df4552e19b9dee59d193f6e7cdd10d4cd55b

PKG_FIXUP:=autoreconf
PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/ngrep
  SECTION:=net
  CATEGORY:=Network
  DEPENDS:=+libpcap +libpcre2
  TITLE:=network grep
  URL:=http://ngrep.sourceforge.net
endef

define Package/ngrep/description
	ngrep a pcap-aware tool that will allow you to specify extended
	regular expressions to match against data payloads of packets. It
	currently recognizes TCP, UDP, and ICMP across Ethernet, PPP, SLIP,
	FDDI, Token Ring and null interfaces, and understands BPF filter
	logic in the same fashion as more common packet sniffing tools,
	like tcpdump and snoop.
endef

TARGET_CFLAGS += -D_DEFAULT_SOURCE

CONFIGURE_ARGS += \
	--enable-pcre2 \
	--disable-dropprivs \
	--with-pcap-includes=$(STAGING_DIR)/opt/include

define Package/ngrep/install	
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/opt/bin/ngrep $(1)/opt/bin
endef

$(eval $(call BuildPackage,ngrep))
