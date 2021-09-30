CFLAGS  += -g -Wall -Werror
LDLIBS   = -lxenctrl -lxenstore

all: varstored-watch

clean:
	rm -f varstored-watch *.o

install:
	install -d ${DESTDIR}/usr/sbin
	install -m 0755 varstored-watch ${DESTDIR}/usr/sbin
