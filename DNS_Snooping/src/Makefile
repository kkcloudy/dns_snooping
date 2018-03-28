OBJS=main.o eloop.o  dns_snooping.o dnss_ubus.o common.o os.o debug.o cache.o util.o nmp_process.o dns_iptables.o 
TARGET=DNS_Snooping
TARGET_CLI=dnss_cli
#FLAGS= -Wall 

INCLUDE += -I $(STAGING_DIR)/usr/include
INCLUDE += -I $(STAGING_DIR)/usr/include/libnl
LDFLAGS += -L$(STAGING_DIR)/usr/lib

LIBS_DEPEND=-lnetfilter_queue -lubus -lubox -luci -lblobmsg_json -ljson-c -lnl-genl-3 -lnl-3

iptcsource = $(BUILD_DIR)/linux-*/iptables-1.4.21/libiptc/.libs/lib*.a

.PHONY:all
all:$(TARGET) $(TARGET_CLI)

.PHONY: clean
clean:
	rm -f $(OBJS) $(TARGET)

$(TARGET):$(OBJS)
	${CC} $^  $(iptcsource) ${LDFLAGS} $(LIBS_DEPEND) -ldl -o $@

$(TARGET_CLI):dnss_cli.o
	${CC} $^ ${LDFLAGS} -o $@

.c.o:
	#${CC} -c ${CFLAGS} ${INC} $< -o $@
	${CC} ${CFLAGS} $(INCLUDE) -c $< -o $@


