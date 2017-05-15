#ifndef _OBFS_OBFSUTIL_H
#define _OBFS_OBFSUTIL_H

int get_head_size(char *plaindata, int size, int def_size);

void init_shift128plus(void);

uint64_t xorshift128plus(void);

int rand_bytes(uint8_t *output, int len);

void memintcopy_lt(void *mem, uint32_t val);

#endif // _OBFS_OBFSUTIL_H
