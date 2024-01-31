LIBS=/usr/lib/libnl-3.so /usr/lib/libnl-route-3.so /usr/lib/libnl-genl-3.so /usr/lib/libmnl.so.0.2.0
INCNL=/usr/include/libnl3/

default: Makefile bond.c
	gcc bond.c $(LIBS) -levent -I$(INCNL) -o bond -Wall -g

prio:
	gcc sysprio.c -o sysprio -Wall -g

clean:
	rm bond sysprio
