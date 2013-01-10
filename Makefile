# $Id: Makefile 2556 2006-03-08 08:15:27Z tormentor $
CC = gcc
LD = gcc
CFLAGS = -I/usr/local/include -g -Wall
LDFLAGS = -L/usr/local/lib -lnetsnmp -lssl -lrrd_th -lpthread
RM = /bin/rm -f

LIBS =

OBJS = mpsnmp.o
PROG = mpsnmp

all: $(PROG)

$(PROG): $(OBJS)
	$(LD) $(LDFLAGS) $(OBJS) $(LIBS) $(FLAGS) -o $(PROG)

%.o: %.c
	$(CC) $(CFLAGS) $(FLAGS) -c $<

clean:
	$(RM) $(PROG) $(OBJS) $(PROG).core ktrace.out

install: all
	strip $(PROG)
	install -m 751 -o root -g wheel $(PROG) /usr/local/bin

