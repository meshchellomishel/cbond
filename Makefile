LIBS=/usr/lib/libnl-3.so /usr/lib/libnl-route-3.so /usr/lib/libnl-genl-3.so /usr/lib/libmnl.so.0.2.0
INC=/usr/include/libnl3/

default: Makefile bond.c
	gcc bond.c $(LIBS) -I$(INC) -o bond -Wall -g

clean:
	rm bond
