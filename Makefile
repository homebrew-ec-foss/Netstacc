CC=clang
CFLAGS=-I./include

ODIR = build
SRC = $(wildcard src/*.c)
OBJ = $(patsubst src/%.c,$(ODIR)/%.o,$(SRC))
HEADERS = $(wildcard include/*.h)

TUN_IP = 10.0.0.1/24

help:
	@echo "Available Makefile targets:"
	@echo "  make build   - Compile the source code into the build/ directory"
	@echo "  make run     - Build and run the Netstacc executable (requires sudo)"
	@echo "  make setup   - Configure the tun0 virtual interface (idempotent)"
	@echo "  make clean   - Remove all compiled objects and executable"

run: build
	sudo $(ODIR)/netstacc

$(ODIR)/%.o: src/%.c $(HEADERS)
	@mkdir -p $(ODIR)
	$(CC) -c -o $@ $< $(CFLAGS)

build: $(OBJ)
	$(CC) $(OBJ) -o $(ODIR)/netstacc

.PHONY: clean setup help build run

setup:
	@sudo ip tuntap del dev tun0 mode tun 2>/dev/null || true
	sudo ip tuntap add dev tun0 mode tun user $(USER)
	sudo ip link set dev tun0 up
	sudo ip addr add $(TUN_IP) dev tun0 || true
	@echo "[+] tun0 interface configured successfully!"

clean:
	rm -rf $(ODIR)/*
