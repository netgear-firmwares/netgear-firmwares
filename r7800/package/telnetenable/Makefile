# 
# Copyright (C) 2008 OpenWrt.org
#

include $(TOPDIR)/rules.mk

PKG_NAME:=telnetenable
PKG_RELEASE:=1
PKG_GIT_TREEISH=a30834462f960489f41a4b4a23d617a240cd10fc

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/telnetenable
	SECTION:=utils
	CATEGORY:=Network
	TITLE:=unlocking the utelnetd.
endef

define Build/Prepare
	$(CP) $(GIT_HOME)/telnetenable.git/* $(PKG_BUILD_DIR)/
endef

define Package/telnetenable/install
	install -d -m0755 $(1)/usr/sbin
	install -m0755 $(PKG_BUILD_DIR)/telnetenable $(1)/usr/sbin/
	install -m0755 $(PKG_BUILD_DIR)/telnet_update.sh $(1)/usr/sbin/
#	install -d -m0755 $(1)/lib/network
#	install -m0755 ./files/RtDebug.sh $(1)/lib/network/
	install -d -m0755 $(1)/etc/init.d
	install -m0755 ./files/telnet.init $(1)/etc/init.d/telnet
endef

$(eval $(call BuildPackage,telnetenable))
