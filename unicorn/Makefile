LDFLAGS += $(shell pkg-config --libs glib-2.0) -lpthread -lm -lunicorn

all: main
main:
	gcc $(CFLAGS) src/main.c $(LDFLAGS) -o bin/main
