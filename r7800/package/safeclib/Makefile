#
# Copyright (C) 2006-2013 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=safeclib
PKG_VERSION:=3.3
PKG_RELEASE:=1
PKG_GIT_TREEISH:=C11_V3.3
#PKG_FIXUP:=autoreconf libtool
#PKG_SOURCE:=$(PKG_NAME).tar.gz
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)


TARGET_CFLAGS := -w
#PKG_BUILD_DEPENDS:=USE_UCLIBC

include $(INCLUDE_DIR)/package.mk

define Package/safeclib
  SECTION:=libs
  CATEGORY:=Libraries
  TITLE:=Support C11 safe C library
  DEPENDS:=+libstdcpp +libc
endef

define Build/Prepare
	$(CP) $(GIT_HOME)/safeclib.git/* $(PKG_BUILD_DIR)/
endef


define Build/Configure
endef


define Build/Compile
endef



define Build/InstallDev
	$(INSTALL_DIR) $(STAGING_DIR)/usr/include
	$(CP) $(PKG_BUILD_DIR)/include/* $(STAGING_DIR)/usr/include/ 
	$(CP) $(PKG_BUILD_DIR)/include/libsafec/* $(STAGING_DIR)/usr/include/ 
	$(INSTALL_DIR) $(STAGING_DIR)/usr/lib
	$(CP) $(PKG_BUILD_DIR)/src/libsafec-3.3.a $(STAGING_DIR)/usr/lib/
	$(CP) $(PKG_BUILD_DIR)/src/libsafec-3.3.so* $(STAGING_DIR)/usr/lib/
	$(CP) $(PKG_BUILD_DIR)/src/pkgconfig $(STAGING_DIR)/usr/lib/
endef

define Package/safeclib/install
	$(INSTALL_DIR) $(1)/usr/include
	$(CP) $(PKG_BUILD_DIR)/include/libsafec/* $(1)/usr/include/
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_BUILD_DIR)/src/* $(1)/usr/lib/
endef


$(eval $(call BuildPackage,safeclib))
