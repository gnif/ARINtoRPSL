#include "util.h"

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <bstring.h>

static uint64_t fnv1a64(const void *data, size_t len)
{
  const uint8_t *p = (const uint8_t *)data;
  uint64_t h = 14695981039346656037ULL;
  for (size_t i = 0; i < len; i++)
  {
    h ^= (uint64_t)p[i];
    h *= 1099511628211ULL;
  }
  return h;
}

static uint64_t mix64(uint64_t x)
{
  x ^= x >> 30;
  x *= 0xbf58476d1ce4e5b9ULL;
  x ^= x >> 27;
  x *= 0x94d049bb133111ebULL;
  x ^= x >> 31;
  return x;
}

size_t arin_orgid_from_handle(char *out, size_t out_sz,
                              const void *handle, size_t handle_len,
                              uint32_t attempt)
{
  uint64_t h = fnv1a64(handle, handle_len);

  h ^= ((uint64_t)attempt + 0x9e3779b97f4a7c15ULL);
  h = mix64(h);

  char letters[5];
  uint64_t t = h;
  for (int i = 0; i < 4; i++)
  {
      letters[3 - i] = (char)('A' + (t % 26));
      t /= 26;
  }
  letters[4] = '\0';

  uint32_t num = (uint32_t)(h % 99999ULL) + 1U;

  int n = snprintf(out, out_sz, "ORG-%s%u-ARIN", letters, num);
  if (n < 0 || (size_t)n >= out_sz) return 0;
  return (size_t)n;
}

int parse_ipv4_decimal(const bstring_t * bs, struct in_addr *out)
{
  const unsigned char *p   = (const unsigned char *)bs->buf;
  const unsigned char *end = p + bs->len;

  uint32_t parts[4];

  for (int i = 0; i < 4; i++) {
    if (p >= end || !isdigit(*p)) return 0;

    unsigned val = 0;
    int digits = 0;

    while (p < end && isdigit(*p)) {
      val = val * 10u + (unsigned)(*p - (unsigned char)'0');
      if (val > 255u) return 0;
      p++;
      if (++digits > 3) return 0;
    }

    parts[i] = (uint32_t)val;

    if (i < 3) {
      if (p >= end || *p != (unsigned char)'.') return 0;
      p++;
    }
  }

  if (p != end)
    return 0;

  uint32_t host = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
  out->s_addr = htonl(host);
  return 1;
}

int parse_ipv6_decimal(const bstring_t *bs, struct in6_addr *out)
{
  char tmp[INET6_ADDRSTRLEN];
  if (bs->len >= INET6_ADDRSTRLEN)
    return 0;

  memcpy(tmp, bs->buf, bs->len);
  tmp[bs->len] = 0;
  return inet_pton(AF_INET6, tmp, (void*)out);
}

uint8_t ipv4_to_cidr(const struct in_addr *start, const struct in_addr *end)
{
  uint32_t diff = ntohl(start->s_addr) ^ ntohl(end->s_addr);
  return (diff == 0) ? 32 : (uint8_t)__builtin_clz((unsigned)diff);
}

uint8_t ipv6_to_cidr(const struct in6_addr *start, const struct in6_addr *end)
{
  const uint8_t *a = start->s6_addr;
  const uint8_t *b = end->s6_addr;

  unsigned prefix = 0;

  for (int i = 0; i < 16; ++i) {
    uint8_t d = (uint8_t)(a[i] ^ b[i]);
    if (d == 0) {
      prefix += 8;
      continue;
    }

    prefix += (unsigned)__builtin_clz((unsigned)d) - (unsigned)(sizeof(unsigned) * 8u - 8u);
    break;
  }

  return (uint8_t)prefix;
}
