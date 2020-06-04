HELPER_PATH ?= /usr/local/lib/afl

all:	afl_shmem_module.so

afl_shmem_module.so:	afl_shmem_module.so.c
	$(CC) $(CFLAGS) -g -O2 -fPIC -shared -I. -O3 afl_shmem_module.so.c -o afl_shmem_module.so -ldl -lrt
	cp -f afl_shmem_module.so ../..

debug:
	$(CC) $(CFLAGS) -g -D_DEBUG=1 -O2 -fPIC -shared -I. -O3 afl_shmem_module.so.c -o afl_shmem_module.so -ldl -lrt
	cp -f afl_shmem_module.so ../..
	

install: afl_shmem_module.so
	install -m 0755 afl_shmem_module.so $(HELPER_PATH)

clean:
	rm -f afl_shmem_module.so ../../afl_shmem_module.so *~ core
