OBJS = auth-plug.o
RUSTLIB = target/release/libchipin_mqtt_auth_plugin.a

CFLAGS := $(CFG_CFLAGS)
CFLAGS += -I$(MOSQUITTO_SRC)/src/
CFLAGS += -I$(MOSQUITTO_SRC)/lib/
ifneq ($(OS),Windows_NT)
	CFLAGS += -fPIC -Wall -Werror
endif
CFLAGS += -DDEBUG=1

LDFLAGS := $(CFG_LDFLAGS)
LDFLAGS += -L$(MOSQUITTO_SRC)/lib/ -Ltarget/release/
LDADD = -lchipin_mqtt_auth_plugin

all: chipin_auth_plug.so

chipin_auth_plug.so : $(RUSTLIB) $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -fPIC -shared -o $@ $(OBJS) $(LDADD)

chipin_auth_plug.o: auth-plug.c

$(RUSTLIB) :
	cargo build --release

test :
	cargo test

clean :
	rm -f *.o *.so
	cargo clean
