#ifndef __MPTCPSPLIT_SPLIT_PROCESSING_H
#define __MPTCPSPLIT_SPLIT_PROCESSING_H

#include <vector>
#include "four_tuple.h"
#include "mptcp_connection.h"
#include "connection_map.h"

struct splitter_data_struct{
  ConnectionMap four_tuples;
  std::vector<MPTCPConnection> connections;
  std::vector<int> four_tuple_to_connection;
  std::vector<std::pair<double, double> > durations;
};

void update_found_mapping(struct splitter_data_struct * data_struct,
			  FourTuple * ft,
			  double timestamp,
			  const u_char * packet,
			  const int ip_offset);

void create_new_mapping(struct splitter_data_struct * data_struct,
			FourTuple * ft,
			double timestamp,
			const u_char * packet,
			const int ip_offset);

void update_timestamps(struct splitter_data_struct * data_struct,
		       const int & connection_id,
		       const double & timestamp);

#endif
