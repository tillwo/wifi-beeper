PACKAGE = beeper
VERSION = 0.1

override CFLAGS += -O0 -std=gnu99 -Wall -g -DVERSION="$(VERSION)" 
override LFLAGS += 
LIBS = -lpcap
BINARY = $(PACKAGE)
OBJS = beeper.o radiotap.o
DEPS = 

.PHONY: all strip install clean tar

all: $(BINARY)

$(BINARY): $(OBJS)
	$(CC) $(LFLAGS) $(OBJS) -o $(BINARY) $(LIBS)

%.o: %.c $(DEPS)
	$(CC) -c $(CFLAGS) $<

strip: $(BINARY)
	strip -s $(BINARY)

clean:
	rm -f $(OBJS) $(BINARY)

