CC=clang
CFLAGS=-I./include

ODIR = build
_OBJ = checksum.o classifier.o icmp.o tun.o main.o
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

TUN_IP = 10.0.0.1/24

run :$(ODIR)/netstacc
	sudo $(ODIR)/netstacc

$(ODIR)/%.o: src/%.c
	$(CC) -c -o $@ $< $(CFLAGS)

$(ODIR)/netstacc: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)


.PHONY: clean setup

setup:
	sudo ip tuntap add dev tun0 mode tun
	sudo ip addr add $(TUN_IP) dev tun0
	sudo ip link set up dev tun0

clean:
	rm $(ODIR)/*
