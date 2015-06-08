CC=$(DEVKITPRO)/devkitARM/bin/arm-none-eabi-gcc
CFLAGS=-fPIE -fno-zero-initialized-in-bss -std=gnu99 -mcpu=mpcore -fshort-wchar -Os
ASFLAGS=-nostartfiles -nostdlib
LD=$(DEVKITPRO)/devkitARM/bin/arm-none-eabi-gcc
LDFLAGS=-T linker.x -nodefaultlibs -nostdlib -pie
OBJCOPY=arm-none-eabi-objcopy
OBJCOPYFLAGS=
DATSIZE=0x300

all: code.bin

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

main.o: main.c

svc.o: svc.s
	$(CC) -x assembler-with-cpp -march=armv6k -mtune=mpcore -mfloat-abi=hard -c $^ -o $@

code.elf: main.o svc.o
	$(LD) -o $@ $^ $(LDFLAGS)

code.bin: code.elf
	$(OBJCOPY) -O binary $^ $@

.PHONY: clean

clean:
	rm -rf *~ *.o *.elf *.bin *.dat
