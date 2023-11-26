# 
# Copyright (C) 2008 OpenWrt.org
#

include $(TOPDIR)/rules.mk

PKG_NAME:=cloud
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/cloud
	SECTION:=utils
	CATEGORY:=Network
	DEPENDS:=+libconfig
	TITLE:=check readycloud update
endef

define Build/Prepare
	$(CP) $(GIT_HOME)/cloud.git/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
endef

define Package/cloud/install
	install -d -m0755 $(1)/sbin
	install -m0755 $(PKG_BUILD_DIR)/cloud $(1)/sbin/
endef

$(eval $(call BuildPackage,cloud))
