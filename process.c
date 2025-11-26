#include "process.h"

#include <string.h>
#include <stdbool.h>

struct ProcessStats g_processStats = {0};

enum HandleResult process(hpx_ctrl_t *ctl, hpx_tag_t *tag, HandleFn fn, void *param)
{
  bstring_t s;
  if (!ctl->mmap)
  {
    char data[tag->tag.len];
    memcpy(data, tag->tag.buf, tag->tag.len);
    s = (bstring_t)
    {
      .buf = data,
      .len = tag->tag.len
    };
  }
  else
    s = tag->tag;

  bstring_t b;
  long lno;
  bool expectClose = false;

  while(hpx_get_elem(ctl, &b, NULL, &lno) > 0)
  {
    if (hpx_process_elem(b, tag))
    {
      printf("[%ld] ERROR in element: %.*s\n", lno, b.len, b.buf);
      continue;
    }

    if (tag->type == HPX_CLOSE && tag->tag.len == s.len &&
      memcmp(tag->tag.buf, s.buf, s.len) == 0)
      return HANDLE_RESULT_NEXT;

    if (expectClose)
      return HANDLE_RESULT_ERROR;
      
    if (fn)
    {
      enum HandleResult result = fn(ctl, tag, param);
      switch(result)
      {
        case HANDLE_RESULT_CLOSE:
          expectClose = true;
          continue;

        case HANDLE_RESULT_NEXT:
          continue;

        case HANDLE_RESULT_OK:
          return HANDLE_RESULT_NEXT;

        default:
          return result;
      }
      return result;
    }
  }

  return HANDLE_RESULT_ERROR;
}

enum HandleResult process_int(hpx_ctrl_t *ctl, hpx_tag_t *tag, void *param)
{
  if (tag->type != HPX_LITERAL)
    return HANDLE_RESULT_ERROR;

  int *value = (int*)param;  
  *value = bs_tol(tag->tag);

  return HANDLE_RESULT_CLOSE;
}

enum HandleResult process_str(hpx_ctrl_t *ctl, hpx_tag_t *tag, void *param)
{
  if (tag->type != HPX_LITERAL)
    return HANDLE_RESULT_ERROR;

  bstring_t *value = (bstring_t*)param;  
  *value = tag->tag;

  return HANDLE_RESULT_CLOSE;
}