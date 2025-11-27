#ifndef _H_UTIL_
#define _H_UTIL_

#include <stddef.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <bstring.h>

size_t arin_orgid_from_handle(char *out, size_t out_sz, const void *handle, size_t handle_len, uint32_t attempt);
void sanatize_value(const bstring_t *bs, char *out, size_t out_sz);

int parse_ipv4_decimal(const bstring_t *bs, struct in_addr *out);
int parse_ipv6_decimal(const bstring_t *bs, struct in6_addr *out);

uint8_t ipv4_to_cidr(const struct in_addr  *start, const struct in_addr  *end);
uint8_t ipv6_to_cidr(const struct in6_addr *start, const struct in6_addr *end);

#endif