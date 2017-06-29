// 
// mptcpparser.cc
// 
#include <pcap.h>    // pcap
#include <iostream>  // cerr
#include <map>       // map
#include <stdlib.h>  // atoi
#include <unistd.h>  // optarg
#include <vector>

#include "processing.h"
#include "connection_map.h"
#include "mptcp_connection.h"
#include "plotter.h"
#include "options.h"

using namespace std;

int main(int argc, char *argv[]){
  pcap_t *descr;                   // Needed when processing pcap file.
  char errbuf[PCAP_ERRBUF_SIZE];   
  struct pcap_pkthdr * pkthdr;
  const u_char * pktdata;
  unsigned int datalink_type;
  
  char * pcap_fname = handle_options(argc, argv);
  if (pcap_fname == NULL){
    cerr << "Exiting." << endl;
    return 1;
  }
  
  // MEMORY TO PASS AROUND AND REUSE
  int link_layer_offset = -1;   // Uninitialized value. will be set once the
                                // pcap file is opened.

  // CONNECTION AND SUBFLOW TRACKING

  struct connection_data_struct conn_data;

  double timestamp = 0.0;
  int connection_id;
  
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
      store_timestamp(pkthdr, &timestamp);
      
      store_subflow_information(&conn_data, &link_layer_offset,
				pktdata, datalink_type);
           
      store_mp_capable_information(&conn_data,
				   &link_layer_offset, pktdata,
				   datalink_type, &timestamp);
      
      connection_id = get_connection_id(&conn_data,
					&link_layer_offset,
					pktdata,
					datalink_type);
      
      if (connection_id >= 0){
	// process the packet with the proper connection.
	process_packet(&conn_data,
		       &link_layer_offset,
		       pktdata,
		       datalink_type,
		       connection_id,
		       timestamp);
      }
    }
  }
  pcap_close(descr);
  //  END PASS 1

  /*
   *  START PASS 2 - 
   *  Check for data packets that exist without DSS mappings.
   *  Try to find the DSN that matches a subflow sequence
   *  number from the "extended mappings" we have stored.
   */
  descr = open_pcap_for_read(pcap_fname, errbuf,
			     &link_layer_offset,
			     &datalink_type);
  if (!descr){
    cerr << "Exiting." << endl;
    return 1;
  }
  if (link_layer_offset >= 0){  // This means we support the link type
    while (pcap_next_ex(descr, &pkthdr, &pktdata) > 0){
      store_timestamp(pkthdr, &timestamp);
      connection_id = get_connection_id(&conn_data,
					&link_layer_offset,
					pktdata,
					datalink_type);
      if (connection_id >= 0){
	// check for blank tcp payloads and try to plot them
	handle_bare_tcp(&conn_data, &link_layer_offset, pktdata,
			datalink_type, connection_id, timestamp);
      }
    }
  }
  pcap_close(descr);
  

  //  END PASS 2

  
  // FINISH WITH DISPLAYING AND CLEANUP

  if (get_lflag()){
    display_long_connections(&conn_data);
  } else if(get_bflag()){
    display_connections(&conn_data.mptcp_connections);
  }
  clean_up_plotters(&conn_data.mptcp_plotters);
  clean_up_mappings(&conn_data.mptcp_sequence_mappings);
  
  return 0;
}

