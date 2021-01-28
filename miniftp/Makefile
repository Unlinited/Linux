CC=gcc
CFLAGS=-Wall -g
OBJS=bitftp.o sysutil.o session.o ftpproto.o privparent.o str.o privsock.o parseconf.o tunable.o hash.o
LIBS=-lcrypt
BIN=bitftp

$(BIN):$(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)
%.o:%.c
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY:clean
clean:
	rm -fr *.o $(BIN)