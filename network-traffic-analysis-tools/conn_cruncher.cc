#include <pcap.h>    // pcap
#include <iostream>  // cerr
#include <map>       // map
#include <stdlib.h>  // atoi
#include <unistd.h>  // optarg
#include <vector>

#include "subflow.h"
#include "processing.h"
#include "options.h"
#include "conn_crunch_processing.h"
#include "parser_utility.h"
#include "dss.h"
#include "conn_cruncher_stats.h"

using namespace std;

int main(int argc, char *argv[]){
  pcap_t *descr;                   // Needed when processing pcap file.
  char errbuf[PCAP_ERRBUF_SIZE];

  struct pcap_pkthdr * pkthdr;
  const u_char * pktdata;
  unsigned int datalink_type;
  int connection_number = -1;
  
  char * pcap_fname = cruncher_handle_options(argc, argv, &connection_number);
  if (pcap_fname == NULL){
    cerr << "Exiting." << endl;
    return 1;
  }
  
  // MEMORY TO PASS AROUND AND REUSE
  int link_layer_offset = -1;   // Uninitialized value. will be set once the
                                // pcap file is opened.

  // CONNECTION AND SUBFLOW TRACKING

  double timestamp = 0.0;
  int subflow_id = -1;

  struct conn_cruncher_data_struct split_data;
  struct packet_handler_struct pkt_struct;

  initialize_cruncher_data(&split_data);
  
  /*
   *  START PASS 1-
   *  Walk through file and store MP_CAPABLE information in 
   *  separate connections. Make sure both sides are trying to 
   *  use the same version. Warn if they are not.
   */
  descr = open_pcap_for_read(pcap_fname, errbuf, &link_layer_offset, &datalink_type);
  if (!descr){
    cerr << "Exiting." << endl;
    return 1;
  }

  if (link_layer_offset >= 0){  // This means we support the link type
    while (pcap_next_ex(descr, &pkthdr, &pktdata) > 0){
      if (is_ipv4(datalink_type, pktdata)
	  && is_ipv4_tcp(pktdata, link_layer_offset)){

	store_timestamp(pkthdr, &timestamp);
	FourTuple ft = get_ipv4_tcp_four_tuple(pktdata, link_layer_offset);

	if (split_data.four_tuples.exists(ft)){
	  update_found_mapping(&split_data, &ft, timestamp,
			       pktdata, link_layer_offset);
	} else {
	  create_new_mapping(&split_data, &ft, timestamp,
			     pktdata, link_layer_offset);
	}
	subflow_id = split_data.four_tuples.find(ft)->second;
	Subflow * process_this = NULL;
	if (ft == split_data.subflows[subflow_id].get_ft()){
	  process_this = &split_data.subflows[subflow_id];
	} else {
	  process_this = &split_data.reverse_subflows[subflow_id];
	}

	pkt_struct.direction = process_this->get_direction();
	pkt_struct.subflow = process_this;
	pkt_struct.pktdata = pktdata;
	pkt_struct.link_layer_offset = &link_layer_offset;
	pkt_struct.timestamp = &timestamp;

	subflow_packet_handler(&split_data, &pkt_struct);
	connection_packet_handler(&split_data, &pkt_struct);
	clear_subflow_packet(&pkt_struct);
      }
    }
  }

  if (get_cruncher_sflag()){
    display_subflows(&split_data);
  }
  if (get_cruncher_cflag()){
    ConnCruncherStats cc_stats(&split_data);
    cc_stats.display();
    // calc connection level stuff and display
  }

  cleanup_cruncher_data(&split_data);
  
  return 0;
}
