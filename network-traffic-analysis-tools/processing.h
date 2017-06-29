#ifndef __MPTCPPARSER_PROCESSING_H
#define __MPTCPPARSER_PROCESSING_H

#include <vector>
#include <pcap.h>

#include "connection_map.h"
#include "plotter.h"


#include "layer_handlers.h"
#include "mptcpparser.h"
#include "four_tuple.h"
#include "dss.h"
#include "mapping.h"

struct connection_data_struct{
  ConnectionMap subflows;
  ConnectionMap mp_capable_subflows;
  ConnectionMap mp_join_subflows;
  std::vector<MPTCPConnection> mptcp_connections;
  std::vector<Plotter*> mptcp_plotters;
  std::vector<Mapper*> mptcp_sequence_mappings;
  std::map<int,int> subflow_to_connection_id;
};


pcap_t * open_pcap_for_read(char *pcap_fname,
			    char *errbuf,
			    int *link_layer_offset,
			    unsigned int * datalink_type);

void store_subflow_information(struct connection_data_struct * conn_data,
			       int * link_layer_offset,
			       const u_char * pkt_data,
			       unsigned int datalink_type);

void ipv4_subflow_information(struct connection_data_struct * conn_data,
			      int * link_layer_offset,
			      const u_char * pkt_data);

void store_mp_capable_information(struct connection_data_struct * conn_data,
				  int * link_layer_offset,
				  const u_char * pkt_data,
				  unsigned int datalink_type,
				  double * timestamp);

void ipv4_mp_capable_information(struct connection_data_struct * conn_data,
				 int * link_layer_offset,
				 const u_char * pkt_data,
				 double * timestamp);

int get_connection_id(struct connection_data_struct * conn_data,
		      int * link_layer_offset,
		      const u_char * pkt_data,
		      unsigned int datalink_type);

int get_ipv4_connection_id(struct connection_data_struct * conn_data,
			   int * link_layer_offset,
			   const u_char * pkt_data);
			   

void process_packet(struct connection_data_struct * conn_data,
		    int * link_layer_offset,
		    const u_char * pkt_data,
		    unsigned int datalink_type,
		    unsigned int index,
		    double timestamp);
		    

void ipv4_process_packet(struct connection_data_struct * conn_data,
			 int * link_layer_offset,
			 const u_char * pkt_data,
			 unsigned int index,
			 double timestamp);

void handle_bare_tcp(struct connection_data_struct * conn_data,
		    int * link_layer_offset,
		    const u_char * pkt_data,
		    unsigned int datalink_type,
		    unsigned int index,
		     double timestamp);

void handle_bare_ipv4_tcp(struct connection_data_struct * conn_data,
			  int * link_layer_offset,
			  const u_char * pkt_data,
			  unsigned int index,
			  double timestamp);

void display_connections(std::vector<MPTCPConnection> * mptcp_connections);

void display_long_connections(struct connection_data_struct * conn_data);

void store_timestamp(const struct pcap_pkthdr * pkthdr, double * timestamp);

void clean_up_plotters(std::vector<Plotter*> * plotters);

void clean_up_mappings(std::vector<Mapper*> * mappings);

#endif
