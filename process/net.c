#include "../process.h"
#include "../util.h"

#include <stdint.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <string.h>
#include <assert.h>

#define MAX_NETBLOCKS 1024

typedef union IPAddr
{
  struct in_addr  v4;
  struct in6_addr v6;
}
IPAddr;

typedef struct NetBlock
{
  bstring_t startAddress;
  bstring_t endAddress;
  bstring_t type;
  bool      duplicate;
}
NetBlock;

typedef struct NetBlocks
{
  unsigned  count;
  NetBlock *blocks;  
}
NetBlocks;

static enum HandleResult process_netblock(hpx_ctrl_t *ctl, hpx_tag_t *tag, void *param)
{
  if (tag->type != HPX_OPEN)
    return HANDLE_RESULT_ERROR;

  bstring_t b;
  long lno;

  void    *fnParam;
  HandleFn fn;

  NetBlocks *blocks = (NetBlocks*)param;
  if (blocks->count == MAX_NETBLOCKS)
    return HANDLE_RESULT_ERROR;


  NetBlock  *block  = &blocks->blocks[blocks->count];
  *block = (NetBlock){0};

  while(hpx_get_elem(ctl, &b, NULL, &lno) > 0)
  {
    if (hpx_process_elem(b, tag))
    {
      printf("[%ld] ERROR in element: %.*s\n", lno, b.len, b.buf);
      continue;
    }

    if (tag->type == HPX_OPEN)
    {
      if (bs_cmp(tag->tag, "startAddress") == 0)
      {
        fn      = process_str;
        fnParam = &block->startAddress;
      }
      else if (bs_cmp(tag->tag, "endAddress") == 0)
      {
        fn      = process_str;      
        fnParam = &block->endAddress;
      }
      else if (bs_cmp(tag->tag, "type") == 0)
      {
        fn      = process_str;      
        fnParam = &block->type;
      }
      else
        continue;

      assert(fn && fnParam);
      if (process(ctl, tag, fn, fnParam) == HANDLE_RESULT_ERROR)
        return HANDLE_RESULT_ERROR;     
      continue;
    }

    if (tag->type == HPX_CLOSE && bs_cmp(tag->tag, "netBlock") == 0)
      break;
  }

  // check we found all the fields we need
  if (!block->startAddress.len ||
      !block->endAddress.len ||
      !block->type.len)
    return HANDLE_RESULT_OK;

  ++blocks->count;
  return HANDLE_RESULT_OK;
}

/* ARIN netBlock type codes */
enum ArinNetType
{
  ARIN_NETTYPE_UNKNOWN = 0,
  ARIN_NETTYPE_DS, /* Direct allocation */
  ARIN_NETTYPE_DA, /* Direct assignment */
  ARIN_NETTYPE_A,  /* Reallocated */
  ARIN_NETTYPE_S   /* Reassigned */
};

/* IPv4 inetnum status (RIPE-style) */
enum InetnumStatus
{
  STATUS_ALLOCATED_PA = 0,
  STATUS_SUBALLOCATED_PA,
  STATUS_ASSIGNED_PA,
  STATUS_ASSIGNED_PI
};

/* IPv6 inet6num status (RIPE-style) */
enum Inet6numStatus
{
  STATUS6_ALLOCATED_BY_RIR = 0,
  STATUS6_ALLOCATED_BY_LIR,
  STATUS6_AGGREGATED_BY_LIR,
  STATUS6_ASSIGNED,
  STATUS6_ASSIGNED_PI,
  STATUS6_ASSIGNED_ANYCAST
};

enum InetnumStatus
{
  STATUS_ALLOCATED_PA,
  STATUS_SUBALLOCATED_PA,
  STATUS_ASSIGNED_PA,
  STATUS_ASSIGNED_PI
};

#define TAG2(a,b) ((uint16_t)(((uint16_t)(uint8_t)(a) << 8) | (uint16_t)(uint8_t)(b)))

static enum ArinNetType parseArinNetType(const bstring_t *str)
{
  if (!str || !str->buf || str->len == 0)
    return ARIN_NETTYPE_UNKNOWN;

  /* ARIN codes are 1 or 2 chars; anything longer -> unknown */
  if (str->len > 2)
    return ARIN_NETTYPE_UNKNOWN;

  char a = (char)str->buf[0];
  char b = (str->len > 1) ? (char)str->buf[1] : '\0';

  switch (TAG2(a, b))
  {
    case TAG2('D','S'): return ARIN_NETTYPE_DS;
    case TAG2('D','A'): return ARIN_NETTYPE_DA;
    case TAG2('A','\0'): return ARIN_NETTYPE_A;
    case TAG2('S','\0'): return ARIN_NETTYPE_S;
    default: return ARIN_NETTYPE_UNKNOWN;
  }
}

#undef TAG2

static enum InetnumStatus arinTypeToInetnumStatus_v4(enum ArinNetType t)
{
  switch (t)
  {
    case ARIN_NETTYPE_DS: return STATUS_ALLOCATED_PA;       /* Direct allocation */
    case ARIN_NETTYPE_A:  return STATUS_SUBALLOCATED_PA;    /* Reallocated */
    case ARIN_NETTYPE_S:  return STATUS_ASSIGNED_PA;        /* Reassigned */
    case ARIN_NETTYPE_DA: return STATUS_ASSIGNED_PI;        /* Direct assignment */
    default:              return STATUS_ALLOCATED_PA;
  }
}

static enum Inet6numStatus arinTypeToInet6numStatus_v6(enum ArinNetType t)
{
  switch (t)
  {
    case ARIN_NETTYPE_DS: return STATUS6_ALLOCATED_BY_RIR;
    case ARIN_NETTYPE_A:  return STATUS6_ALLOCATED_BY_LIR;
    case ARIN_NETTYPE_S:  return STATUS6_ASSIGNED;
    case ARIN_NETTYPE_DA: return STATUS6_ASSIGNED_PI;
    default:              return STATUS6_ALLOCATED_BY_RIR;
  }
}

static const char* inetnumStatusToStr(enum InetnumStatus s)
{
  switch (s)
  {
    case STATUS_ALLOCATED_PA:      return "ALLOCATED PA";
    case STATUS_SUBALLOCATED_PA:   return "SUB-ALLOCATED PA";
    case STATUS_ASSIGNED_PA:       return "ASSIGNED PA";
    case STATUS_ASSIGNED_PI:       return "ASSIGNED PI";
    default:                       return "ALLOCATED PA";
  }
}

static const char* inet6numStatusToStr(enum Inet6numStatus s)
{
  switch (s)
  {
    case STATUS6_ALLOCATED_BY_RIR: return "ALLOCATED-BY-RIR";
    case STATUS6_ALLOCATED_BY_LIR: return "ALLOCATED-BY-LIR";
    case STATUS6_AGGREGATED_BY_LIR:return "AGGREGATED-BY-LIR";
    case STATUS6_ASSIGNED:         return "ASSIGNED";
    case STATUS6_ASSIGNED_PI:      return "ASSIGNED PI";
    case STATUS6_ASSIGNED_ANYCAST: return "ASSIGNED ANYCAST";
    default:                       return "ALLOCATED-BY-RIR";
  }
}

enum HandleResult process_net(hpx_ctrl_t *ctl, hpx_tag_t *tag, void *param)
{
  bstring_t b;
  long lno;

  void    *fnParam;
  HandleFn fn;

  bstring_t name         = {0};
  bstring_t orgHandle    = {0};
  int       version      = 0;
  bstring_t startAddress = {0};
  bstring_t endAddress   = {0};

  static NetBlock blockBuffer[MAX_NETBLOCKS];
  NetBlocks blocks =
  {
    .blocks = blockBuffer,
    .count  = 0
  };

  while(hpx_get_elem(ctl, &b, NULL, &lno) > 0)
  {
    if (hpx_process_elem(b, tag))
    {
      printf("[%ld] ERROR in element: %.*s\n", lno, b.len, b.buf);
      continue;
    }

    if (tag->type == HPX_OPEN)
    {
      if (bs_cmp(tag->tag, "version") == 0)
      {
        fn      = process_int;
        fnParam = &version;
      }
      else if (bs_cmp(tag->tag, "name") == 0)
      {
        fn      = process_str;
        fnParam = &name;
      }
      else if (bs_cmp(tag->tag, "orgHandle") == 0)
      {
        fn      = process_str;
        fnParam = &orgHandle;
      }
      else if (bs_cmp(tag->tag, "netBlocks") == 0)
      {
        fn      = process_netblock,
        fnParam = &blocks;
      }
      else if (bs_cmp(tag->tag, "startAddress") == 0)
      {
        fn      = process_str;
        fnParam = &startAddress;
      }
      else if (bs_cmp(tag->tag, "endAddress") == 0)
      {
        fn      = process_str;      
        fnParam = &endAddress;
      }
      else 
        continue;

      if (process(ctl, tag, fn, fnParam) == HANDLE_RESULT_ERROR)
        return HANDLE_RESULT_ERROR;

      continue;
    }

    if (tag->type == HPX_CLOSE && bs_cmp(tag->tag, "net") == 0)
      break;
  }

#ifdef DEBUG_LIMIT_RESULTS
  {
    if (g_processStats.netCount == 1000)
      return HANDLE_RESULT_OK;
    bool found = false;
    for(int i = 0; i < g_processStats.dbgCount; ++i)
    {
      if (g_processStats.dbgOrgs[i].len != orgHandle.len)
        continue;

      if (memcmp(g_processStats.dbgOrgs[i].buf, orgHandle.buf, orgHandle.len) == 0)
      {
        found = true;
        break;
      }
    }
    if (!found)
      return HANDLE_RESULT_OK;
  }
#endif  

  //check we have the minimum required fields
  if (!orgHandle.len || (version != 4 && version != 6))
    return HANDLE_RESULT_OK;

  struct
  {
    struct
    {
      IPAddr start, end;
      enum ArinNetType status;
    }
    ranges[MAX_NETBLOCKS];
    unsigned count;
  }
  ipAddrSet = {};

  IPAddr sAddr, eAddr;

  // if the outer address is set, add it to the array
  if (startAddress.len && endAddress.len && ((
    version == 4 && parse_ipv4_decimal(&startAddress, &sAddr.v4) &&
                    parse_ipv4_decimal(&endAddress  , &eAddr.v4)
  ) || (
    version == 6 && parse_ipv6_decimal(&startAddress, &sAddr.v6) &&
                    parse_ipv6_decimal(&endAddress  , &eAddr.v6)
  )))
  {
    ipAddrSet.count = 1;
    ipAddrSet.ranges[0].status = ARIN_NETTYPE_DS;
    ipAddrSet.ranges[0].start  = sAddr;
    ipAddrSet.ranges[0].end    = eAddr;
  }

  // add all the found blocks to the array if they are unique
  if (version == 4)
  {
    for(unsigned i = 0; i < blocks.count; ++i)
    {
      NetBlock * block = &blocks.blocks[i];
      if (!parse_ipv4_decimal(&block->startAddress, &sAddr.v4) ||
          !parse_ipv4_decimal(&block->endAddress  , &eAddr.v4))
        continue;

      bool found = false;
      for(int n = 0; n < ipAddrSet.count; ++n)
      {
        auto range = &ipAddrSet.ranges[n];
        if (range->start.v4.s_addr == sAddr.v4.s_addr &&
            range->end  .v4.s_addr == eAddr.v4.s_addr)
        {
          // use the block type
          if (n == 0)
            range->status = parseArinNetType(&block->type);

          found = true;
          break;
        }
      }

      if (found)
        continue;
      
      if (ipAddrSet.count == MAX_NETBLOCKS)
        break;

      auto range = &ipAddrSet.ranges[ipAddrSet.count++];
      range->start  = sAddr;
      range->end    = eAddr;
      range->status = parseArinNetType(&block->type);
    }
  }
  else
  {
    for(unsigned i = 0; i < blocks.count; ++i)
    {
      NetBlock * block = &blocks.blocks[i];
      if (!parse_ipv6_decimal(&block->startAddress, &sAddr.v6) ||
          !parse_ipv6_decimal(&block->endAddress  , &eAddr.v6))
        continue;

      bool found = false;
      for(int n = 0; n < ipAddrSet.count; ++n)
      {
        auto range = &ipAddrSet.ranges[n];
        if (IN6_ARE_ADDR_EQUAL(&range->start, &sAddr.v6) &&
            IN6_ARE_ADDR_EQUAL(&range->end   ,&eAddr.v6))
        {
          // use the block type
          if (n == 0)
            range->status = parseArinNetType(&block->type);

          found = true;
          break;
        }
      }

      if (found)
        continue;

      if (ipAddrSet.count == MAX_NETBLOCKS)
        break;

      auto range = &ipAddrSet.ranges[ipAddrSet.count++];
      range->start  = sAddr;
      range->end    = eAddr;
      range->status = parseArinNetType(&block->type);
    }
  }

  // finally print the records out
  for(int i = 0; i < ipAddrSet.count; ++i)
  {
    auto range = &ipAddrSet.ranges[i];
    char sStr[INET6_ADDRSTRLEN];
    char eStr[INET6_ADDRSTRLEN];

    if (version == 4)
    {
      inet_ntop(AF_INET , &range->start.v4, sStr, sizeof(sStr));
      inet_ntop(AF_INET , &range->end  .v4, eStr, sizeof(eStr));
    }
    else
    {
      inet_ntop(AF_INET6, &range->start.v6, sStr, sizeof(sStr));
      inet_ntop(AF_INET6, &range->end  .v6, eStr, sizeof(eStr));
    }

    const char * statusStr;

    if (version == 4)
    {
      statusStr = inetnumStatusToStr(arinTypeToInetnumStatus_v4(range->status));
      printf("inetnum:  %s - %s\n", sStr, eStr);
    }
    else
    {
      statusStr = inet6numStatusToStr(arinTypeToInet6numStatus_v6(range->status));
      int cdir = ipv6_to_cidr(&range->start.v6, &range->end.v6);
      printf("inet6num: %s/%d\n", sStr, cdir);
      //printf("inet6num:  %s - %s\n", sStr, eStr);
    }

    char orgId[128];
    arin_orgid_from_handle(orgId, sizeof(orgId), orgHandle.buf, orgHandle.len, 0);

    printf(
      "netname:  %.*s\n"
      "descr:    From ARIN Bulk WHOIS (net)\n"
      "country:  US\n"
      "status:   %s\n"
      "org:      %s\n"
      "admin-c:  DUMY-ARIN\n"
      "tech-c:   DUMY-ARIN\n"
      "mnt-by:   ARIN-MNT\n"
      "source:   ARIN\n"
      "\n",
      name.len, name.buf,
      statusStr,
      orgId);

  }
  ++g_processStats.netCount;
  return HANDLE_RESULT_OK;
}