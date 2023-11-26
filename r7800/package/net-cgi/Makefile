# 
# Copyright (C) 2009 OpenWrt.org
#

include $(TOPDIR)/rules.mk

PKG_NAME:=net-cgi
PKG_RELEASE:=1
PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

WEB_PATH:=www

include $(INCLUDE_DIR)/package.mk

PKG_GIT_TREEISH:=7e761068f937ea7b4c2c07d464996eae6f084bf4

TARGET_CFLAGS += -fstack-protector -Wl,-z,now -Wl,-z,relro -fPIE -pie

define Package/net-cgi
  SECTION:=utils
  CATEGORY:=Base system
  DEFAULT:=y
  DEPENDS:=+lib-dni-common-api +ntgrcrypt
  TITLE:=The mini_httpd CGI interface
endef


define Build/Prepare
	$(CP) $(GIT_HOME)/net-cgi.git/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
endef

define Build/Configure
endef
define Package/net-cgi/install
	$(CP) -rf $(PKG_BUILD_DIR)/Binary/* $(1)/
endef

$(eval $(call BuildPackage,net-cgi))
