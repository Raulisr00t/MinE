#include <Windows.h>
#include <intrin.h>
#include <stdio.h>

#include "mine.h"

int main(int argc, const char* argv[]) {
	LPCSTR AppName = argv[1];

	if (argc != 2) {
		printf("[!] Please Provide ELF binary for Execute in Windows\n");
		return 1;
	}
	
	if (!CheckApp(AppName)) 
		return 1;

	MineRun(AppName);
	return 0;
}
