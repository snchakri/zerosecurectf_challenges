/*
 * K1 kernel (userland model). The out-of-order scheduler's lock waits form this
 * wait-for graph: task i (holding resource i) waits on resource next[i]. There
 * is exactly one circular wait -- a deadlock. The scheduler detects it (Floyd's
 * cycle find), recovers, and reports the cycle. The cycle is the key.
 */
#include <stdio.h>

#define N 14
static int next[N] = { 3, 12, 10, 12, 12, 10, 0, 3, 10, 5, 0, 5, 5, 0 };

int main(void) {
    /* out-of-order scheduling eventually drives the wait pointers into a cycle */
    int slow = 0, fast = 0;
    do { slow = next[slow]; fast = next[next[fast]]; } while (slow != fast);

    int cyc[N], L = 0, cur = slow;
    do { cyc[L++] = cur; cur = next[cur]; } while (cur != slow);

    int mi = 0;                      /* rotate to minimum-first (canonical) */
    for (int i = 1; i < L; i++) if (cyc[i] < cyc[mi]) mi = i;

    fprintf(stderr, "scheduler: circular wait detected, recovering...\n");
    printf("DEADLOCK CYCLE:");
    for (int i = 0; i < L; i++) printf(" %d", cyc[(mi + i) % L]);
    printf("\n");
    return 0;
}
