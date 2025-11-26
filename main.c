#include "util.h"
#include "process.h"

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>

#include <bstring.h>
#include <libhpxml.h>

enum HandleResult process_bulkwhois(hpx_ctrl_t *ctl, hpx_tag_t *tag, void *param)
{
  if (tag->type != HPX_OPEN)
    return HANDLE_RESULT_NEXT;

  if (bs_cmp(tag->tag, "net") == 0)
    return process(ctl, tag, process_net, param);

  if (bs_cmp(tag->tag, "org") == 0)
    return process(ctl, tag, process_org, param);

  return process(ctl, tag, NULL, NULL);
}

int main(int argc, char *argv[])
{
  int fd;
  hpx_ctrl_t *ctl;
  hpx_tag_t  *tag;
  bstring_t   b;
  long        lno;

  if (argc != 2)
  {
    fprintf(stderr, "Invalid usage, expected path to arin_db.xml\n");
    return EXIT_FAILURE;
  }

  if ((fd = open(argv[1], O_RDONLY)) < 0)
  {
    perror("open");
    return EXIT_FAILURE;
  }

  off_t size = lseek(fd, 0, SEEK_END);
  lseek(fd, 0, SEEK_SET);

  if ((ctl = hpx_init(fd, -size)) == NULL)
  {
    perror("hpx_init_simple");
    return EXIT_FAILURE;
  }

  if ((tag = hpx_tm_create(64)) == NULL)
  {
    perror("hpx_tm_create");
    return EXIT_FAILURE;
  }

  printf(
    "mntner:  ARIN-MNT\n"
    "admin-c: DUMY-ARIN\n"
    "upd-to:  unread@arin.net\n"
    "auth:    MD5-PW $1$SaltSalt$DummifiedMD5HashValue\n"
    "mnt-by:  ARIN-MNT\n"
    "source:  ARIN\n"
    "\n"
    "person:  Placeholder Person Object\n"
    "address: Address\n"
    "country: US\n"
    "phone:   +12 345 6789\n"
    "e-mail:  dummy@dummy.com\n"
    "nic-hdl: DUMY-ARIN\n"
    "mnt-by:  ARIN-MNT\n"
    "source:  ARIN\n"
    "\n");

  while(hpx_get_elem(ctl, &b, NULL, &lno) > 0)
  {
    if (hpx_process_elem(b, tag))
    {
      printf("[%ld] ERROR in element: %.*s\n", lno, b.len, b.buf);
      continue;
    }

    if (tag->type == HPX_OPEN && bs_cmp(tag->tag, "bulkwhois") == 0)
    {
      if (process(ctl, tag, process_bulkwhois, NULL) == HANDLE_RESULT_ERROR)
        break;
    }
  }

  hpx_tm_free(tag);
  hpx_free(ctl);
  close(fd);

  fprintf(stderr,
    "STATS:\n"
    "  orgs: %u\n"
    "  nets: %u\n"
    " TOTAL: %u\n",
    g_processStats.orgCount,
    g_processStats.netCount,
    g_processStats.netCount + g_processStats.orgCount
  );  

  return EXIT_SUCCESS;
}