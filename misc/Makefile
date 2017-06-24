rm=/bin/rm -f
CC= cc
DEFS=  
PROGNAME= gen_test_vectors
INCLUDES=  -I.
LIBS=`pkg-config --libs libsodium`


DEFINES= $(INCLUDES) $(DEFS) -DSYS_UNIX=1
CFLAGS= -g $(DEFINES) `pkg-config --cflags libsodium`

SRCS = gen_test_vectors.c  

OBJS = gen_test_vectors.o  

.c.o:
	$(rm) $@
	$(CC) $(CFLAGS) -c $*.c

all: $(PROGNAME)

$(PROGNAME) : $(OBJS)
	$(CC) $(CFLAGS) -o $(PROGNAME) $(OBJS) $(LIBS)

clean:
	$(rm) $(OBJS) $(PROGNAME) core *~
