#include <pcap.h>    // pcap
#include <iostream>  // cerr
#include <map>       // map
#include <stdlib.h>  // atoi
#include <unistd.h>  // optarg
#include <vector>

#include "processing.h"
#include "options.h"
#include "split_processing.h"

using namespace std;

int main(int argc, char *argv[]){
  pcap_t *descr;                   // Needed when processing pcap file.
  char errbuf[PCAP_ERRBUF_SIZE];

  struct pcap_pkthdr * pkthdr;
  const u_char * pktdata;
  unsigned int datalink_type;
  int connection_number = -1;
  
  char * pcap_fname = split_handle_options(argc, argv, &connection_number);
  if (pcap_fname == NULL){
    cerr << "Exiting." << endl;
    return 1;
  }
  
  // MEMORY TO PASS AROUND AND REUSE
  int link_layer_offset = -1;   // Uninitialized value. will be set once the
                                // pcap file is opened.

  // CONNECTION AND SUBFLOW TRACKING

  double timestamp = 0.0;
  int four_tuple_id;
  
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

  struct splitter_data_struct conn_data;

  string test_file = get_split_oname();
  
  pcap_t * pcap_open_val = pcap_open_dead(datalink_type, 65535);
  pcap_dumper_t * pcap_dumper = pcap_dump_open(pcap_open_val, test_file.c_str());
  
  
  unsigned int tcp_v4_pkts = 0;
  if (link_layer_offset >= 0){  // This means we support the link type
    while (pcap_next_ex(descr, &pkthdr, &pktdata) > 0){
      if (is_ipv4(datalink_type, pktdata)
	  && is_ipv4_tcp(pktdata, link_layer_offset)){

	store_timestamp(pkthdr, &timestamp);
	FourTuple ft = get_ipv4_tcp_four_tuple(pktdata, link_layer_offset);

	if (conn_data.four_tuples.exists(ft)){
	  update_found_mapping(&conn_data, &ft, timestamp,
			       pktdata, link_layer_offset);
	} else {
	  create_new_mapping(&conn_data, &ft, timestamp,
			     pktdata, link_layer_offset);
	}
	

	four_tuple_id = conn_data.four_tuples.find(ft)->second;
	update_timestamps(&conn_data, conn_data.four_tuple_to_connection[four_tuple_id], timestamp);
	
	if (conn_data.four_tuple_to_connection[four_tuple_id] == connection_number){
	  pcap_dump((u_char*)pcap_dumper, pkthdr, pktdata);
	  pcap_dump_flush(pcap_dumper);
	  // ouput packet data	
	  tcp_v4_pkts++;
	}
      }
    }
  }

  if (get_split_nflag()){
    cout << fixed;
    cout << "Number of packets written: " << tcp_v4_pkts;
    cout << ". Connection number: " << connection_number << endl;
  }
  if (get_split_lflag()){
    for (unsigned int i = 0; i < conn_data.connections.size(); i++){
      FourTuple ft = conn_data.connections[i].get_source_tuple();
      cout << fixed;
      cout << ft.get_src_string() << " " << i << " ";
      cout << conn_data.durations[i].first << " ";
      cout << conn_data.durations[i].second << " ";
      cout << (conn_data.durations[i].second - conn_data.durations[i].first) << endl;
    }
  }
  return 0;
}
