#include "../process.h"
#include "../util.h"

enum HandleResult process_org(hpx_ctrl_t *ctl, hpx_tag_t *tag, void *param)
{
  bstring_t b;
  long lno;

  void    *fnParam;
  HandleFn fn;

  bstring_t name   = {0};
  bstring_t handle = {0};

  while(hpx_get_elem(ctl, &b, NULL, &lno) > 0)
  {
    if (hpx_process_elem(b, tag))
    {
      printf("[%ld] ERROR in element: %.*s\n", lno, b.len, b.buf);
      continue;
    }

    if (tag->type == HPX_OPEN)
    {
      if (bs_cmp(tag->tag, "name") == 0)
      {
        fn      = process_str;
        fnParam = &name;
      }
      else if (bs_cmp(tag->tag, "handle") == 0)
      {
        fn      = process_str;
        fnParam = &handle;
      }
      else 
        continue;

      if (process(ctl, tag, fn, fnParam) == HANDLE_RESULT_ERROR)
        return HANDLE_RESULT_ERROR;

      continue;
    }

    if (tag->type == HPX_CLOSE && bs_cmp(tag->tag, "org") == 0)
      break;
  }

#ifdef DEBUG_LIMIT_RESULTS
  if (g_processStats.dbgCount == (sizeof(g_processStats.dbgOrgs) / sizeof(*g_processStats.dbgOrgs)))
    return HANDLE_RESULT_OK;
  g_processStats.dbgOrgs[g_processStats.dbgCount++] = handle;    
#endif

  char orgId[128];
  arin_orgid_from_handle(orgId, sizeof(orgId), handle.buf, handle.len, 0);

  char orgName[name.len + 1], *p = orgName;
  for(int i = 0; i < name.len; ++i)
  {
    // remove '#' characters from the name as it is read as a comment
    if (name.buf[i] == '#')
      continue;

    // replace non-ascii characters with a space
    if (name.buf[i] < 32 || name.buf[i] > 126)
    {
      // don't insert multiple spaces
      if (i > 0 && *(p-1) == ' ')
        continue;

      *p = ' ';
      continue;
    }

    *p = name.buf[i];
    ++p;
  }
  *p = '\0';

  printf(
    "organisation: %s\n"    
    "org-name:     %s\n"
    "org-type:     OTHER\n"
    "remarks:      ARIN orgHandle: %.*s\n"
    "mnt-by:       ARIN-MNT\n"
    "source:       ARIN\n"
    "\n",
    orgId,    
    orgName,
    handle.len, handle.buf
  );
  ++g_processStats.orgCount;

  return HANDLE_RESULT_OK;
}