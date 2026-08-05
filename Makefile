CC=clang
CFLAGS=-I./include

ODIR = build
SRC = $(wildcard src/*.c)
OBJ = $(patsubst src/%.c,$(ODIR)/%.o,$(SRC))
HEADERS = $(wildcard include/*.h)

TUN_IP = 10.0.0.1/24

run : build 
	$(ODIR)/netstacc

$(ODIR)/%.o: src/%.c $(HEADERS)
	$(CC) -c -o $@ $< $(CFLAGS)

build: $(OBJ)
	$(CC) $(OBJ) -o $(ODIR)/netstacc

.PHONY: clean setup

setup:
	sudo ip tuntap add dev tun0 mode tun user $(USER)
	sudo ip addr add $(TUN_IP) dev tun0
	sudo ip link set up dev tun0

clean:
	rm $(ODIR)/*
