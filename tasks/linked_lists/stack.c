#include "stack.h"

#include <linux/slab.h>
#include <linux/gfp.h>


stack_entry_t* create_stack_entry(void *data)
{
    stack_entry_t* stack_entry = kmalloc(sizeof(stack_entry_t), GFP_KERNEL);

    if (stack_entry) {
        INIT_LIST_HEAD(&stack_entry->lh);
        stack_entry->data = data;
    }

    return stack_entry;
}

void delete_stack_entry(stack_entry_t *entry)
{
    kfree(entry);
}

void stack_push(struct list_head *stack, stack_entry_t *entry)
{
    list_add(&entry->lh, stack);
}

stack_entry_t* stack_pop(struct list_head *stack)
{
    stack_entry_t* entry = list_first_entry_or_null(stack, stack_entry_t, lh);;
    if (!list_empty(stack)) {
        list_del(stack->next);
    }
    return entry;
}
