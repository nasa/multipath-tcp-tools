#ifndef __CONN_CRUNCHER_CONN_CRUNCHER_STATS_H
#define __CONN_CRUNCHER_CONN_CRUNCHER_STATS_H

#include "conn_crunch_processing.h"


class ConnCruncherStats{
 public:
  ConnCruncherStats();
  ConnCruncherStats(struct conn_cruncher_data_struct * data);

  void display();
  
 private:
  struct conn_cruncher_data_struct * data_ptr;
};

#endif
