#include <sys/mman.h>
#include <unistd.h>
#include <linux/kernel.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>

void allocate_with_mmap() {
	uint64_t result_size = 0;
	size_t cur_cize = 1000000000000000;

	while (cur_cize > 1) {
		void* result = mmap(0, cur_cize, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
		if (result == MAP_FAILED) {
			cur_cize = cur_cize / 2;
		} else {
			result_size = result_size + cur_cize;
		}
	}
	printf("Result allocated size = %" PRIu64 "\n", result_size);
}

int main()
{
	// size_t PAGE_SIZE = getpagesize();
	allocate_with_mmap();
    return 0;
}
