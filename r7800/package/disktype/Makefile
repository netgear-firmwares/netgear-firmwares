#
# Copyright (C) 2010 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=disktype
PKG_VERSION:=1
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)
include $(INCLUDE_DIR)/package.mk

define Package/disktype
  SECTION:=utils
  CATEGORY:=Utilities
  DEPENDS:=@TARGET_ipq806x +lib-dni-common-api
  TITLE:=Disk format detection
  SUBMENU:=Disk Management.
endef

TARGET_CFLAGS+=-fstack-protector -fpie -pie -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro

define Package/disktype/description
	disktype is used to detect the 200M EFI partition
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef


MAKE_FLAGS += CC="$(TARGET_CC) $(TARGET_CFLAGS) $(LDFLAGS) $(EXTRA_LDFLAGS)"

define Package/disktype/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/$(PKG_NAME) $(1)/usr/sbin/
endef

$(eval $(call BuildPackage,disktype))
