all: setitimer-helper squish-pty squish-unix

LDFLAGS = -lm

setitimer-helper: setitimer-helper.c
	gcc -o setitimer-helper setitimer-helper.c $(LDFLAGS)

squish-pty: squish-pty.c
	gcc -o squish-pty squish-pty.c $(LDFLAGS)

squish-unix: squish-unix.c
	gcc -o squish-unix squish-unix.c $(LDFLAGS)

clean: 
	rm -f *.o setitimer-helper squish-pty squish-unix
