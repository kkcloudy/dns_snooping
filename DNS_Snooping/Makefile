include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=DNS_Snooping
PKG_VERSION:=2017.11.3
PKG_RELEASE:=1

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

export FILENO_PATH=$(TOPDIR)/fileno/$(TARGET_DIR_NAME)
export FILENO_BIN=$(SCRIPT_DIR)/fileno

define Package/DNS_Snooping
  SECTION:=hos
  CATEGORY:=hos
  SUBMENU:=apps
  DEPENDS:=+libnetfilter-queue +libnfnetlink +libubus +ubus +libubox +ubusd +jshn +libuci +libjson-c \
           +iptables-mod-extra +iptables-mod-ipopt +iptables-mod-iprange  +iptables-mod-nat-extra +libnl
  TITLE:=DNS Snooping
endef

define Package/DNS_Snooping/description
	DNS Snooping
endef


#TARGET_CFLAGS += \
#	-I$(AUTELAN_LIBS)
#	-I$(STAGING_DIR)/usr/include \

#TARGET_LDFLAGS += \
#	-L$(STAGING_DIR)/usr/lib
define Build/Prepare
	rm -rf $(PKG_BUILD_DIR)
	mkdir -p $(PKG_BUILD_DIR)/src
	$(CP) ./src/* $(PKG_BUILD_DIR)/src
	rm -rf $(STAGING_DIR)/usr/include/linux
	mkdir -p $(STAGING_DIR)/usr/include/linux
	$(CP) $(TOOLCHAIN_DIR)/include/linux/netfilter $(STAGING_DIR)/usr/include/linux
	mkdir -p $(FILENO_PATH)
endef
		
define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR)/src/ \
	CC="$(TARGET_CC)" \
	AR=$(TARGET_CROSS)ar \
	STAGING_DIR="$(STAGING_DIR)" \
	BUILD_DIR="$(BUILD_DIR)"
endef

define Package/DNS_Snooping/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/DNS_Snooping $(1)/usr/sbin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/dnss_cli $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/DNS_Snooping $(1)/etc/init.d/DNS_Snooping
	#$(INSTALL_DIR) $(1)/etc/config
	#$(INSTALL_CONF) ./files/DNS_Snooping.conf $(1)/etc/config/DNS_Snooping
	$(INSTALL_DIR) $(1)/bin
	$(CP) ./files/libnetfilter_queue.so.1 $(1)/bin/
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/bash/*.sh $(1)/usr/bin/
endef

$(eval $(call BuildPackage,DNS_Snooping))
