#ifndef _H_PROCESS_
#define _H_PROCESS_

//#define DEBUG_LIMIT_RESULTS

#include <libhpxml.h>

enum HandleResult
{
  HANDLE_RESULT_OK,
  HANDLE_RESULT_NEXT,
  HANDLE_RESULT_CLOSE,
  HANDLE_RESULT_ERROR
};
typedef enum HandleResult (*HandleFn)(hpx_ctrl_t *ctl, hpx_tag_t *tag, void *param);

enum HandleResult process(hpx_ctrl_t *ctl, hpx_tag_t *tag, HandleFn fn, void *param);
enum HandleResult process_int(hpx_ctrl_t *ctl, hpx_tag_t *tag, void *param);
enum HandleResult process_str(hpx_ctrl_t *ctl, hpx_tag_t *tag, void *param);

struct ProcessStats
{
  unsigned orgCount;
  unsigned netCount;

#ifdef DEBUG_LIMIT_RESULTS
  bstring_t dbgOrgs[1000];
  unsigned  dbgCount;
#endif
};
extern struct ProcessStats g_processStats;

enum HandleResult process_org(hpx_ctrl_t *ctl, hpx_tag_t *tag, void *param);
enum HandleResult process_net(hpx_ctrl_t *ctl, hpx_tag_t *tag, void *param);

#endif