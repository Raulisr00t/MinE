#include "mine_patch.h"

#include <Windows.h>
#include <stdio.h>
#include <stdint.h>

int MinePatchSyscalls(const MineImage* img)
{
    int total = 0;

    for (int s = 0; s < img->exec_seg_count; s++) {
        uint64_t va   = img->exec_segs[s].va;
        uint64_t size = img->exec_segs[s].size;
        if (!va || size < 2) continue;

        DWORD old_prot;
        if (!VirtualProtect((LPVOID)(uintptr_t)va, (SIZE_T)size,
                PAGE_EXECUTE_READWRITE, &old_prot)) {
            fprintf(stderr, "[MinE-Patch] VirtualProtect(RWX) failed at 0x%llX err=%lu\n",
                (unsigned long long)va, GetLastError());
            continue;
        }

        uint8_t* p   = (uint8_t*)(uintptr_t)va;
        uint8_t* end = p + size - 1;
        int count = 0;

        for (; p < end; p++) {
            if (p[0] == 0x0F && p[1] == 0x05) {
                p[1] = 0x0B;
                count++;
                p++;
            }
        }

        VirtualProtect((LPVOID)(uintptr_t)va, (SIZE_T)size, old_prot, &old_prot);
        FlushInstructionCache(GetCurrentProcess(), (LPCVOID)(uintptr_t)va, (SIZE_T)size);

        if (count > 0)
            printf("[MinE-Patch] Segment 0x%llX: %d syscall(s) -> ud2\n",
                (unsigned long long)va, count);
        total += count;
    }

    printf("[MinE-Patch] Total: %d syscall instruction(s) patched\n", total);
    return total;
}
