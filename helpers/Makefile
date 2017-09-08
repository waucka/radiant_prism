all: flatpak netifs packagekit

flatpak: flatpak.c
	$(CC) flatpak.c -o flatpak $(shell pkg-config --libs --cflags flatpak)

netifs: netifs.c
	$(CC) netifs.c -o netifs

packagekit: packagekit.c
	$(CC) packagekit.c -o packagekit $(shell pkg-config --libs --cflags packagekit-glib2)

clean:
	rm *~ *.o flatpak netifs packagekit

.PHONY: all clean
