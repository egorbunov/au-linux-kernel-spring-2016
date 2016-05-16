#include <fcntl.h>
#include <unistd.h>

#include <mutex.h>
#include <shared_spinlock.h>
#include <mutex_ioctl.h>

static int mutex_dev_fd = -1;

mutex_err_t mutex_init(mutex_t *m)
{
	shared_spinlock_init(&m->spinlock);
	m->kwaiters_cnt = 0;
	mutex_ioctl_lock_create_arg_t arg;
    int ret = ioctl(mutex_dev_fd, MUTEX_IOCTL_LOCK_CREATE, &arg);
    if (ret < 0) {
        return MUTEX_INTERNAL_ERR;
    }
    m->kid = arg.id;
    return MUTEX_OK;
}

mutex_err_t mutex_deinit(mutex_t *m)
{
    m->kwaiters_cnt = 0;
	mutex_ioctl_lock_destroy_arg_t arg;
	arg.id = m->kid;
    int ret = ioctl(mutex_dev_fd, MUTEX_IOCTL_LOCK_DESTROY, &arg);
    if (ret < 0) {
        return MUTEX_INTERNAL_ERR;
    }
    return MUTEX_OK;
}

mutex_err_t mutex_lock(mutex_t *m)
{
	mutex_ioctl_lock_wait_arg_t  arg;
	if (shared_spin_trylock(&m->spinlock)) {
		return MUTEX_OK;
	}

	// going to kernel
	arg.spinlock = &m->spinlock;
	arg.id = m->kid;
	__sync_add_and_fetch(&m->kwaiters_cnt, 1);
	if (ioctl(mutex_dev_fd, MUTEX_IOCTL_LOCK_WAIT, &arg) < 0) {
		__sync_sub_and_fetch(&m->kwaiters_cnt, 1);
		return MUTEX_INTERNAL_ERR;
	}
	__sync_sub_and_fetch(&m->kwaiters_cnt, 1);

    return MUTEX_OK;
}

mutex_err_t mutex_unlock(mutex_t *m)
{
	mutex_ioctl_lock_wake_arg_t arg;

	if (m->kwaiters_cnt == 0) {
		if (shared_spin_unlock(&m->spinlock)) {
			return MUTEX_OK;
		}
		return MUTEX_INTERNAL_ERR;
	}

	// going to kernel
	arg.spinlock = &m->spinlock;
	arg.id = m->kid;
	if (ioctl(mutex_dev_fd, MUTEX_IOCTL_LOCK_WAKE, &arg) < 0) {
		return MUTEX_INTERNAL_ERR;
	}
    return MUTEX_OK;
}

mutex_err_t mutex_lib_init()
{
	if (mutex_dev_fd > 0) {
		return MUTEX_INTERNAL_ERR;
	}
	mutex_dev_fd = open("/dev/mutex", O_RDWR);
	if (mutex_dev_fd < 0) {
		return MUTEX_INTERNAL_ERR;
	}
	return MUTEX_OK;
}

mutex_err_t mutex_lib_deinit()
{
	if (mutex_dev_fd < 0) {
		return MUTEX_INTERNAL_ERR;
	}
	if (close(mutex_dev_fd)) {
		return MUTEX_INTERNAL_ERR;
	}
	mutex_dev_fd = -1;
    return MUTEX_OK;
}
