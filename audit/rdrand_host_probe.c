#include <cpuid.h>
#include <immintrin.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

struct tuple {
    uint64_t q[4];
};

static int tuple_cmp(const void *aa, const void *bb) {
    const struct tuple *a = aa;
    const struct tuple *b = bb;
    for (int i = 0; i < 4; ++i) {
        if (a->q[i] < b->q[i]) return -1;
        if (a->q[i] > b->q[i]) return 1;
    }
    return 0;
}

int main(int argc, char **argv) {
    unsigned long long count = 1000000;
    if (argc > 1) count = strtoull(argv[1], NULL, 10);
    if (count < 4 || count > 100000000ULL || count % 4 != 0) {
        fprintf(stderr, "sample count must be a multiple of four in [4, 100000000]\n");
        return 2;
    }

    unsigned int eax, ebx, ecx, edx;
    if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx) || !(ecx & bit_RDRND)) {
        puts("SKIP: runner CPU does not expose RDRAND");
        return 0;
    }

    uint64_t *values = calloc((size_t)count, sizeof(*values));
    if (!values) {
        perror("calloc values");
        return 2;
    }

    unsigned long long failures = 0;
    unsigned long long adjacent = 0;
    unsigned long long lag4 = 0;
    for (unsigned long long i = 0; i < count; ++i) {
        unsigned long long value = 0;
        int ok = 0;
        for (int retry = 0; retry < 100 && !ok; ++retry) {
            ok = _rdrand64_step(&value);
        }
        if (!ok) {
            ++failures;
            fprintf(stderr, "FAIL: RDRAND failed after 100 retries at sample %llu\n", i);
            free(values);
            return 1;
        }
        values[i] = (uint64_t)value;
        if (i && values[i] == values[i - 1]) ++adjacent;
        if (i >= 4 && values[i] == values[i - 4]) ++lag4;
    }

    size_t tuple_count = (size_t)(count / 4);
    struct tuple *tuples = calloc(tuple_count, sizeof(*tuples));
    if (!tuples) {
        perror("calloc tuples");
        free(values);
        return 2;
    }
    for (size_t i = 0; i < tuple_count; ++i) {
        for (int j = 0; j < 4; ++j) tuples[i].q[j] = values[i * 4 + (size_t)j];
    }
    qsort(tuples, tuple_count, sizeof(*tuples), tuple_cmp);
    unsigned long long repeated_tuples = 0;
    for (size_t i = 1; i < tuple_count; ++i) {
        if (tuple_cmp(&tuples[i - 1], &tuples[i]) == 0) ++repeated_tuples;
    }

    printf("Native runner RDRAND samples: %llu\n", count);
    printf("Adjacent equal qwords: %llu\n", adjacent);
    printf("Equal qwords at distance four: %llu\n", lag4);
    printf("Repeated four-qword nonce tuples: %llu / %zu\n", repeated_tuples, tuple_count);
    puts("LIMIT: this is the runner's exposed RDRAND, not the production host CPU");
    free(tuples);
    free(values);
    return (adjacent || lag4 || repeated_tuples || failures) ? 1 : 0;
}
