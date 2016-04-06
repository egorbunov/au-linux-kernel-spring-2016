#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>

#include "vsd_device.h"
#include "../vsd_driver/vsd_ioctl.h"

static int fd = -1;
static const char* VSD_FILENAME = "/dev/vsd";

int vsd_init()
{
    fd = open(VSD_FILENAME, O_RDWR);
    if (fd < 0) {
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

int vsd_deinit()
{
    return close(fd);
}

int vsd_get_size(size_t *out_size)
{
    vsd_ioctl_get_size_arg_t arg;
    int res = ioctl(fd, VSD_IOCTL_GET_SIZE, &arg);
    if (res < 0) {
        return res;
    }
    *out_size = arg.size;
    return EXIT_SUCCESS;
}

int vsd_set_size(size_t size)
{
    vsd_ioctl_set_size_arg_t arg;
    arg.size = size;
    int res = ioctl(fd, VSD_IOCTL_SET_SIZE, &arg);
    if (res < 0) {
        return res;
    }
    return EXIT_SUCCESS;
}

ssize_t vsd_read(char* dst, off_t offset, size_t size)
{
    int result = lseek(fd, offset, SEEK_SET);
    if (result < 0) {
        return result;
    }
    return read(fd, dst, size);
}

ssize_t vsd_write(const char* src, off_t offset, size_t size)
{
    int result = lseek(fd, offset, SEEK_SET);
    if (result < 0) {
        return EXIT_FAILURE;
    }
    return write(fd, src, size);
}

void* vsd_mmap(size_t offset)
{
    if (offset % (size_t) getpagesize() != 0) {
        return MAP_FAILED;
    }

    size_t size;
    vsd_get_size(&size);

    return mmap(NULL, size - offset, PROT_READ | PROT_WRITE, MAP_SHARED, fd, offset);
}

int vsd_munmap(void* addr, size_t offset)
{
    if (offset % (size_t) getpagesize() != 0) {
        return EXIT_FAILURE;
    }
    
    size_t size;
    vsd_get_size(&size);

    return munmap(addr, size - offset);
}
