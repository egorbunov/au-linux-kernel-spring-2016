#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <uapi/linux/fs.h>
#include <uapi/linux/stat.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/rculist.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/err.h>
#include "mutex_ioctl.h"

#define LOG_TAG "[MUTEX_MODULE] "

/**
 * Mutex state in particular thread group (process)
 */
typedef struct tgroup_mutex {
    struct hlist_node hnode;
    mutex_id_t id;
    spinlock_t wlock;
    wait_queue_head_t wqh;
} tgroup_mutex_t;

/**
 * State, which carry mutex list for particular process
 */
typedef struct tgroup_mutex_state {
    struct hlist_node hnode; // node in list of processes
    pid_t tgid;
    // lock only when adding/deleting mutex
    spinlock_t wlock;
    mutex_id_t next_mid; // seq id. No need to care about overflow.
    struct hlist_head mlist; // list of mutexes in that process (tgid)
} tgroup_mutex_state_t;

/**
 * Top level state, which holds list of per process mutexes states
 */
typedef struct system_mutex_state {
    // lock only when adding/deleting tgroup
    spinlock_t wlock;
    struct hlist_head tgstates;
} system_mutex_state_t;

typedef struct mutex_dev {
    struct miscdevice mdev;
    system_mutex_state_t sysmstate;
} mutex_dev_t;

static mutex_dev_t *mutex_dev;

// TODO implement all the missing

#define lookup_tgroup_mutex_state(itgid) \
({ \
    tgroup_mutex_state_t* tgstate = NULL; \
    hlist_for_each_entry(tgstate, &mutex_dev->sysmstate.tgstates, hnode) { \
        if (tgstate->tgid == (itgid)) { \
            break; \
        } \
    } \
    tgstate; \
})

#define lookup_mutex(tgroup_mstate, mid) \
({ \
    tgroup_mutex_t* mutex = NULL; \
    hlist_for_each_entry(mutex, &(tgroup_mstate)->mlist, hnode) { \
        if (mutex->id == (mid)) { \
            break; \
        } \
    } \
    mutex; \
})

#define init_system_mutex_state(sysmstate) \
do { \
    spin_lock_init(&(sysmstate)->wlock); \
    INIT_HLIST_HEAD(&(sysmstate)->tgstates); \
} while (0);

#define deinit_tg_mutex_state(tgstate) \
do { \
    struct hlist_node* mu_node = NULL; \
    struct hlist_node* q = NULL; \
    tgroup_mutex_t* mstate = NULL; \
    spin_lock(&(tgstate)->wlock); \
    hlist_for_each_safe(mu_node, q, &tgstate->mlist) { \
        mstate = hlist_entry(mu_node, tgroup_mutex_t, hnode); \
        hlist_del_rcu(mu_node); \
        wake_up_interruptible_all(&mstate->wqh); \
        kfree(mstate); \
    } \
    spin_unlock(&(tgstate)->wlock); \
    kfree(tgstate); \
} while(0);

#define deinit_system_mutex_state(sysmstate)\
do { \
    struct hlist_head tmp_tg_list; \
    struct hlist_node* tg_node = NULL; \
    struct hlist_node* q = NULL; \
    tgroup_mutex_state_t* tgstate = NULL; \
    \
    spin_lock(&(sysmstate)->wlock); \
    tmp_tg_list = (sysmstate)->tgstates; \
    INIT_HLIST_HEAD(&(sysmstate)->tgstates); \
    spin_unlock(&(sysmstate)->wlock); \
    synchronize_rcu(); \
    \
    hlist_for_each_safe(tg_node, q, &tmp_tg_list) { \
        tgstate = hlist_entry(tg_node, tgroup_mutex_state_t, hnode); \
        hlist_del_rcu(tg_node); \
        deinit_tg_mutex_state(tgstate); \
    } \
} while(0);


static int mutex_dev_open(struct inode *inode, struct file *filp)
{
    tgroup_mutex_state_t* new_tgstate = NULL;

    new_tgstate = (tgroup_mutex_state_t*) kzalloc(sizeof(tgroup_mutex_state_t), GFP_KERNEL);
    if (!new_tgstate) {
        return -ENOMEM;
    }

    new_tgstate->tgid = current->tgid;
    new_tgstate->next_mid = 0;
    spin_lock_init(&new_tgstate->wlock);
    INIT_HLIST_HEAD(&new_tgstate->mlist);

    spin_lock(&mutex_dev->sysmstate.wlock);
    hlist_add_head_rcu(&new_tgstate->hnode, &mutex_dev->sysmstate.tgstates);
    spin_unlock(&mutex_dev->sysmstate.wlock);

    return 0;
}

static int mutex_dev_release(struct inode *inode, struct file *filp)
{
    tgroup_mutex_state_t *tgstate = NULL;

    rcu_read_lock();
    tgstate = lookup_tgroup_mutex_state(current->tgid);
    if (!tgstate) {
        rcu_read_unlock();
        return -EINVAL;
    }
    spin_lock(&mutex_dev->sysmstate.wlock);
    hlist_del_rcu(&tgstate->hnode);
    spin_unlock(&mutex_dev->sysmstate.wlock);    
    rcu_read_unlock();

    synchronize_rcu();
    deinit_tg_mutex_state(tgstate);
    return 0;
}

static long mutex_ioctl_lock_create(mutex_ioctl_lock_create_arg_t __user *uarg)
{
    tgroup_mutex_state_t* tgstate = NULL;
    mutex_ioctl_lock_create_arg_t arg;
    tgroup_mutex_t* mutex = NULL;

    rcu_read_lock();

    tgstate = lookup_tgroup_mutex_state(current->tgid);
    if (!tgstate) {
        return -EINVAL;
    } 

    arg.id = __sync_fetch_and_add(&tgstate->next_mid, 1);
    mutex = (tgroup_mutex_t*) kzalloc(sizeof(tgroup_mutex_t), GFP_KERNEL);
    if (!mutex) {
        return -ENOMEM;
    }
    mutex->id = arg.id;    
    spin_lock_init(&mutex->wlock);
    init_waitqueue_head(&mutex->wqh);

    spin_lock(&tgstate->wlock);
    hlist_add_head_rcu(&mutex->hnode, &tgstate->mlist);
    spin_unlock(&tgstate->wlock);
    
    tgstate = NULL;
    rcu_read_unlock();

    if (copy_to_user(uarg, &arg, sizeof(arg))) {
        kfree(mutex);
        return -EFAULT;
    }

    return 0;
}

static long mutex_ioctl_lock_destroy(mutex_ioctl_lock_destroy_arg_t __user *uarg)
{
    mutex_ioctl_lock_destroy_arg_t arg;
    tgroup_mutex_state_t *tgstate = NULL;
    tgroup_mutex_t *mutex = NULL;

    if (copy_from_user(&arg, uarg, sizeof(arg))) {
        return -EFAULT;
    }

    rcu_read_lock();
    tgstate = lookup_tgroup_mutex_state(current->tgid);
    if (!tgstate) {
        rcu_read_unlock();
        return -EINVAL;
    }
    mutex = lookup_mutex(tgstate, arg.id);
    if (!mutex) {
        rcu_read_unlock();
        return -EINVAL;
    }

    spin_lock(&tgstate->wlock);
    hlist_del_rcu(&mutex->hnode);
    spin_unlock(&tgstate->wlock);

    tgstate = NULL;
    rcu_read_unlock();

    synchronize_rcu();

    // printk("Destroying mutex; waking up everybody waiting on it!!\n"); 
    wake_up_interruptible_all(&mutex->wqh);
    kfree(mutex);

    return 0;
}

static long mutex_queue_wait(shared_spinlock_t *spinlock, mutex_id_t mid)
{
    DEFINE_WAIT(wait);
    long ret = 0;
    tgroup_mutex_state_t *mstate = NULL;
    tgroup_mutex_t *mutex = NULL;

    rcu_read_lock();
    mstate = lookup_tgroup_mutex_state(current->tgid);
    if (!mstate) {
        rcu_read_unlock();
        return -EINVAL;
    }

    mutex = lookup_mutex(mstate, mid);
    if (!mutex) {
        rcu_read_unlock();
        return -EINVAL;
    }

    spin_lock(&mutex->wlock);
    // Check for probably lost wakeup
    if (!shared_spin_islocked(spinlock)) {
        spin_unlock(&mutex->wlock);
        rcu_read_unlock();
        return 0;
    }

    prepare_to_wait_exclusive(&mutex->wqh, &wait, TASK_INTERRUPTIBLE);
    spin_unlock(&mutex->wlock);
    mstate = NULL;
    mutex = NULL;
    rcu_read_unlock();

    schedule();
    if (signal_pending(current))
        ret = -ERESTARTSYS;

    rcu_read_lock();
    mstate = lookup_tgroup_mutex_state(current->tgid);
    if (!mstate) {
        rcu_read_unlock();
        return -EINVAL;
    }

    mutex = lookup_mutex(mstate, mid);
    if (!mutex) {
        rcu_read_unlock();
        return -EINVAL;
    }
    finish_wait(&mutex->wqh, &wait);
    rcu_read_unlock();

    return ret;
}

static long mutex_ioctl_lock_wait(mutex_ioctl_lock_wait_arg_t *uarg)
{
    long res = 0;
    while (!shared_spin_trylock(uarg->spinlock)) {
        res = mutex_queue_wait(uarg->spinlock, uarg->id);
        if (res != 0) {
            // printk("mutex_queue_wait failed!\n");
            return res;
        }
    }
    return 0;
}

static long mutex_ioctl_lock_wake(mutex_ioctl_lock_wake_arg_t *uarg)
{
    tgroup_mutex_state_t *tgstate = NULL;
    tgroup_mutex_t *mutex = NULL;

    rcu_read_lock();
    tgstate = lookup_tgroup_mutex_state(current->tgid);
    if (!tgstate) {
        rcu_read_unlock();
        return -EINVAL;
    }
    mutex = lookup_mutex(tgstate, uarg->id);
    if (!mutex) {
        rcu_read_unlock();
        return -EINVAL;
    }
    shared_spin_unlock(uarg->spinlock);
    wake_up_interruptible(&mutex->wqh);
    rcu_read_unlock();

    return 0;
}

static long mutex_dev_ioctl(struct file *filp, unsigned int cmd,
        unsigned long arg)
{
    switch(cmd) {
        case MUTEX_IOCTL_LOCK_CREATE:
            return mutex_ioctl_lock_create(
                    (mutex_ioctl_lock_create_arg_t*)arg);
        case MUTEX_IOCTL_LOCK_DESTROY:
            return mutex_ioctl_lock_destroy(
                    (mutex_ioctl_lock_destroy_arg_t*)arg);
        case MUTEX_IOCTL_LOCK_WAIT:
            return mutex_ioctl_lock_wait(
                    (mutex_ioctl_lock_wait_arg_t*)arg);
        case MUTEX_IOCTL_LOCK_WAKE:
            return mutex_ioctl_lock_wake(
                    (mutex_ioctl_lock_wake_arg_t*)arg);
        default:
            return -ENOTTY;
    }
}

static struct file_operations mutex_dev_fops = {
    .owner = THIS_MODULE,
    .open = mutex_dev_open,
    .release = mutex_dev_release,
    .unlocked_ioctl = mutex_dev_ioctl
};

static int __init mutex_module_init(void)
{
    int ret = 0;
    mutex_dev = (mutex_dev_t*)
        kzalloc(sizeof(*mutex_dev), GFP_KERNEL);
    if (!mutex_dev) {
        ret = -ENOMEM;
        pr_warn(LOG_TAG "Can't allocate memory\n");
        goto error_alloc;
    }
    mutex_dev->mdev.minor = MISC_DYNAMIC_MINOR;
    mutex_dev->mdev.name = "mutex";
    mutex_dev->mdev.fops = &mutex_dev_fops;
    mutex_dev->mdev.mode = S_IRUSR | S_IRGRP | S_IROTH
        | S_IWUSR| S_IWGRP | S_IWOTH;
    init_system_mutex_state(&mutex_dev->sysmstate);

    if ((ret = misc_register(&mutex_dev->mdev)))
        goto error_misc_reg;

    pr_notice(LOG_TAG "Mutex dev with MINOR %u"
        " has started successfully\n", mutex_dev->mdev.minor);
    return 0;

error_misc_reg:
    kfree(mutex_dev);
    mutex_dev = NULL;
error_alloc:
    return ret;
}

static void __exit mutex_module_exit(void)
{
    pr_notice(LOG_TAG "Removing mutex device %s\n", mutex_dev->mdev.name);
    misc_deregister(&mutex_dev->mdev);
    deinit_system_mutex_state(&mutex_dev->sysmstate);
    kfree(mutex_dev);
    mutex_dev = NULL;
}

module_init(mutex_module_init);
module_exit(mutex_module_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("AU user space mutex kernel side support module");
MODULE_AUTHOR("Kernel hacker!");
