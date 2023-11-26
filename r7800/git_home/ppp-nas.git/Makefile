#
#	haiyue.wang @ 2007/03/13
#	Simple is the best, I love Linux Kernel & Network :-)
#

CC = gcc

FILES = main.o pppnas.o session.o route.o iprule.o iproute.o dni_system.o

CFLAGS += -Wall -Wunused -g -O2

all : ppp-nas

ppp-nas : $(FILES)
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) $(FILES) -o $@ $(LDFLAGS)
	@echo "make $@ finished on `date`"

%.o : %.c
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -c $<

clean:
	rm -f *.o 
	rm -f ppp-nas
