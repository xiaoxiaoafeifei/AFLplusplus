
all: spawn

spawn:
	$(CC) -static-libgcc -fPIC -m64 -ffunction-sections -fdata-sections -Wall -Os -pipe -g3 afl-frida-spawn.c -o afl-frida-spawn -L. -lfrida-core -ldl -lm -ldl -lm -ldl -lrt -ldl -lrt -ldl -ldl -lresolv -ldl -lrt -lm -Wl,--export-dynamic -Wl,--gc-sections,-z,noexecstack -pthread
