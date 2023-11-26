#
#	Copyright (C) 2008 Delta Networks Inc.
#
all: telnetenable

CFLAGS += -Wall -Wunused -g -O2

FILES = blowfish.o md5.o telnetenable.o

%.o: %.c
	$(CC) $(CFLAGS) -c $<

telnetenable: $(FILES)
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	rm -f *.o telnetenable
