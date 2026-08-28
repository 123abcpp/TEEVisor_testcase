#include "../enclave_runtime/ocall.h"

#define PAGE_SIZE_BYTES 0x1000UL
#define COW_RESERVE_BYTES (100UL * 1024UL * 1024UL)

static void print_cycles(const char *label, size_t label_len, uint64_t cycles)
{
    char output[64];
    char digits[20];
    size_t digit_count = 0;
    size_t output_len = 0;

    while (output_len < label_len) {
        output[output_len] = label[output_len];
        output_len++;
    }

    do {
        digits[digit_count++] = '0' + cycles % 10;
        cycles /= 10;
    } while (cycles);

    while (digit_count)
        output[output_len++] = digits[--digit_count];
    output[output_len++] = '\n';

    ocall_print(output, output_len);
}

int runtime_test_case(void)
{
    unsigned long user_heap_size = GET_ENCLAVE_TLS(user_heap_size);
    if (user_heap_size <= COW_RESERVE_BYTES) {
        ocall_print("user heap is too small for COW test\n",
                    sizeof("user heap is too small for COW test\n"));
        return -1;
    }
    unsigned long cow_size = user_heap_size - COW_RESERVE_BYTES;

    struct ocall_clone *clone = malloc_shared(8, sizeof(*clone));
    struct eclone_metatdata *metadata = malloc_shared(64, sizeof(*metadata));
    if (!clone || !metadata) {
        ocall_print("clone metadata allocation failed\n",
                    sizeof("clone metadata allocation failed\n"));
        if (clone)
            free_shared(clone);
        if (metadata)
            free_shared(metadata);
        return -1;
    }

    clone->metadata = metadata;
    int ret = do_eclone(clone);
    free_shared(clone);
    free_shared(metadata);

    void *cow_range = malloc_user(PAGE_SIZE_BYTES, cow_size);
    if (!cow_range) {
        ocall_print("COW allocation failed\n", sizeof("COW allocation failed\n"));
        return -1;
    }

    ocall_print("COW_BEGIN\n", sizeof("COW_BEGIN\n"));
    __asm__ volatile("lfence" ::: "memory");
    uint64_t cow_start = rdtsc();
    for (size_t offset = 0; offset < cow_size; offset += PAGE_SIZE_BYTES)
        *(volatile unsigned char *)(cow_range + offset) = 1;
    __asm__ volatile("lfence" ::: "memory");
    uint64_t cow_end = rdtsc();
    ocall_print("COW_END\n", sizeof("COW_END\n"));
    print_cycles("COW_TRIGGER_CYCLES=", sizeof("COW_TRIGGER_CYCLES=") - 1,
                 cow_end - cow_start);

    /* Enclave destruction immediately reclaims the COW allocation. */
    return ret;
}
