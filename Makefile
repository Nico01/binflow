CFLAGS = -Wall
LDFLAGS = -lcapstone

all: binflow traceme

binflow: main.o elf.o maps.o trace.o util.o disas.o
	${CC} ${CFLAGS} $^ -o $@ ${LDFLAGS}

traceme: traceme.o
	${CC} ${CFLAGS} $^ -o $@

%.o: %.c
	${CC} ${CFLAGS} -c $^ -o $@

.PHONY: clean
clean:
	rm -f *.o binflow traceme
