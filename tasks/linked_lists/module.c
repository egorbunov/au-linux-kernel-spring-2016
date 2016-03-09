#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>

#include "stack.h"
#include "assert.h"

static void __init test_stack(void)
{
    LIST_HEAD(data_stack);
    stack_entry_t *tos = NULL;
    const char *tos_data = NULL;
    const char* test_data[] = { "1", "2", "3", "4" };
    long i = 0;

    pr_alert("Testing basic stack");

    for (i = 0; i != ARRAY_SIZE(test_data); ++i) {
        stack_push(&data_stack,
            create_stack_entry((void*)test_data[i])
        );
    }

    for (i = ARRAY_SIZE(test_data) - 1; i >= 0; --i) {
        tos = stack_pop(&data_stack);
        tos_data = STACK_ENTRY_DATA(tos, const char*);
        delete_stack_entry(tos);
        printk(KERN_ALERT "%s == %s\n", tos_data, test_data[i]);
        assert(!strcmp(tos_data, test_data[i]));
    }

    assert(stack_empty(&data_stack));
}

static int __init print_processes_backwards(void)
{
    int result = 0;
    stack_entry_t* proc_entry;
    struct task_struct* proc;
    char* exe_name;
    LIST_HEAD(proc_stack);

    pr_alert("Printing processes backwards");

    for_each_process(proc) {
        exe_name = kmalloc(TASK_COMM_LEN, GFP_KERNEL);
        if (!exe_name) {
            result = -ENOMEM;
            goto p_exit;
        }

        proc_entry = create_stack_entry((void*)exe_name);
        if (!proc_entry) {
            kfree(exe_name);
            result = -ENOMEM;
            goto clean_stack;
        }

        exe_name = get_task_comm(exe_name, proc);
        stack_push(&proc_stack, proc_entry);
    }

    while (!stack_empty(&proc_stack)) {
        proc_entry = stack_pop(&proc_stack);
        exe_name = STACK_ENTRY_DATA(proc_entry, char*);
        printk(KERN_ALERT "Process executable name: [ %s ]\n", exe_name);
        kfree(exe_name);
        delete_stack_entry(proc_entry);
    }
    goto p_exit;

clean_stack:
    while (!stack_empty(&proc_stack)) {
        proc_entry = stack_pop(&proc_stack);
        exe_name = STACK_ENTRY_DATA(proc_entry, char*);
        kfree(exe_name);
        delete_stack_entry(proc_entry);
    }
p_exit:
    return result;
}

static int __init ll_init(void)
{
    printk(KERN_ALERT "Hello, linked_lists\n");
    test_stack();
    print_processes_backwards();
    return 0;
}

static void __exit ll_exit(void)
{
    printk(KERN_ALERT "Goodbye, linked_lists!\n");
}

module_init(ll_init);
module_exit(ll_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Linked list exercise module");
MODULE_AUTHOR("Kernel hacker!");
