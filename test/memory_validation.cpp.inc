#include <cstring>

#include "bytebuffer/memory.h"

size_t memory_allocations = 0;

void* test_malloc(size_t size) {
    auto ptr = malloc(size);
    memory_allocations++;
    return ptr;
}

void* test_calloc(size_t num, size_t size) {
    auto ptr = malloc(size * num);
    memory_allocations++;
    memset(ptr, 0, size * num);
    return ptr;
}

void* test_realloc(void* ptr, size_t new_size) {
    auto new_ptr = malloc(new_size);
    memory_allocations++;
    memcpy(new_ptr, ptr, new_size);
    free(ptr);
    memory_allocations--;
    return new_ptr;
}

void test_free(void* ptr) {
    // lzav frees nullptr
    if (ptr != nullptr) {
        memory_allocations--;
        free(ptr);
    }
}

size_t check_allocated_memory() {
    return memory_allocations;
}

void set_test_memory_allocator() {
    ossp_allocator allocator = {
        test_malloc,
        test_calloc,
        test_realloc,
        test_free,
    };
    set_extern_allocator(allocator);
}

void* debug_allocf(mrb_state* mrb, void* ptr, size_t size, void* ud) {
    (void)mrb;
    (void)ud;
    auto ext_alloc = ossp_extern_allocator;
    if (size == 0) {
        ext_alloc->free_fn(ptr);
        return nullptr;
    }

    if (!ptr) {
        return ext_alloc->malloc_fn(size);
    }

    return ext_alloc->realloc_fn(ptr, size);
}