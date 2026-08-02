CC=clang
CFLAGS=-I./include

SRC = $(wildcard src/*.c)
ODIR = build
OBJ = $(patsubst src/%.c,build/%.o,$(SRC))

TUN_IP = 10.0.0.1/24

run : netstacc
	sudo $(ODIR)/netstacc


$(ODIR)/%.o: src/%.c
	$(CC) -c -o $@ $< $(CFLAGS)

netstacc: $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o build/netstacc


.PHONY: clean setup

setup:
	sudo ip tuntap add dev tun0 mode tun
	sudo ip addr add $(TUN_IP) dev tun0
	sudo ip link set up dev tun0

clean:
	rm $(ODIR)/*
