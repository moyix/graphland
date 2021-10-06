all: graphland

graphland: graphland.o
	$(CC) -Wall -o $@ $<

clean:
	rm -f graphland.o graphland
