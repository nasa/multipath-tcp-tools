#ifndef __CONN_CRUNCHER_CONN_CRUNCH_PROCESSING_H
#define __CONN_CRUNCHER_CONN_CRUNCH_PROCESSING_H

#include <vector>
#include "four_tuple.h"
#include "connection_map.h"
#include "subflow.h"
#include "mptcp_connection.h"

struct conn_cruncher_data_struct{
  ConnectionMap four_tuples;
  std::vector<Subflow> subflows;
  std::vector<Subflow> reverse_subflows;
  std::vector<int> four_tuple_to_subflow;
  MPTCPConnection * connection;
  Subflow orig_dir_subflow;
  Subflow remote_dir_subflow;
};

struct packet_handler_struct{
  Subflow * subflow;
  const u_char * pktdata;
  const int * link_layer_offset;
  const double * timestamp;
  int direction;
};

void update_found_mapping(struct conn_cruncher_data_struct * data_struct,
			  FourTuple * ft,
			  double timestamp,
			  const u_char * packet,
			  const int ip_offset);

void create_new_mapping(struct conn_cruncher_data_struct * data_struct,
			FourTuple * ft,
			double timestamp,
			const u_char * packet,
			const int ip_offset);

void subflow_packet_handler(struct conn_cruncher_data_struct * data_struct,
			    struct packet_handler_struct * pkt_struct);

void connection_packet_handler(struct conn_cruncher_data_struct * data_struct,
			       struct packet_handler_struct * pkt_struct);

void clear_subflow_packet(struct packet_handler_struct * pkt_struct);

void initialize_cruncher_data(struct conn_cruncher_data_struct * data_struct);

void cleanup_cruncher_data(struct conn_cruncher_data_struct * data_struct);

void display_subflows(struct conn_cruncher_data_struct * data_struct);

#endif
