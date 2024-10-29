CFLAGS  += -g -Wall -Werror
LDLIBS   = -lxenstore -lselinux

all: svirt-interpose

clean:
	rm -f svirt-interpose *.o

install:
	install -d ${DESTDIR}/usr/sbin
	install -m 0755 svirt-interpose ${DESTDIR}/usr/sbin
