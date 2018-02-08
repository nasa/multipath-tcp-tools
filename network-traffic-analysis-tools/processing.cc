#include "processing.h"
#include "options.h"

using namespace std;

static bool g_bare_warning(false);

pcap_t * open_pcap_for_read(char *pcap_fname, char *errbuf, int *link_layer_offset, unsigned int * datalink_type){
  pcap_t *descr = pcap_open_offline(pcap_fname, errbuf);
  if (descr == NULL){
    cerr << "pcap_open_offline() failed: " << errbuf << endl;
    return NULL;
  }
  cerr << "Opened file with data link type: " << pcap_datalink(descr) << endl;
  if (pcap_datalink(descr) == DLT_LINUX_SLL){
    (*link_layer_offset) = sizeof(struct sll_header);
    (*datalink_type) = DLT_LINUX_SLL;
  } else if (pcap_datalink(descr) == DLT_EN10MB){
    (*link_layer_offset) = sizeof(struct ethhdr);
    (*datalink_type) = DLT_EN10MB;
  }
  else {
    cerr << "Link layer format not currently supported.\n\n";
    return NULL;
  }
  return descr;
}

void store_subflow_information(struct connection_data_struct * conn_data, int * link_layer_offset, const u_char * pkt_data, unsigned int datalink_type){
  // If IPv6, log an error and return. Not yet supported.
  if (is_ipv6(datalink_type, pkt_data)){
    cerr << "Warning: IPv6 support not yet implemented." << endl;
    return;
  }

  // If IPv4, find and store both addresses
  if (is_ipv4(datalink_type, pkt_data)){
    ipv4_subflow_information(conn_data, link_layer_offset, pkt_data);
  }
}

void ipv4_subflow_information(struct connection_data_struct * conn_data,
			      int * link_layer_offset,
			      const u_char * pkt_data){
  // Only work on connections where we see the first SYN
  if (is_ipv4_tcp_syn(pkt_data, *link_layer_offset) &&
      !is_ipv4_tcp_ack(pkt_data, *link_layer_offset)){

    FourTuple ft = get_ipv4_tcp_four_tuple(pkt_data, *link_layer_offset);

    if (contains_ipv4_mptcp_option(pkt_data, *link_layer_offset, MP_JOIN)){
      uint32_t token = get_ipv4_mp_join_token(pkt_data, *link_layer_offset);
      bool is_done = false;
      int match_index = -1;
      for (unsigned int i = 0; !is_done && i < conn_data->mptcp_connections.size(); i++){
	if (conn_data->mptcp_connections[i].src_token_matches(token)){
	  ft.reverse();
	  match_index = i;
	  is_done = true;
	} else if (conn_data->mptcp_connections[i].dst_token_matches(token)){
	  match_index = i;
	  is_done = true;
	}
      }
      if (conn_data->mp_capable_subflows.exists(ft)){
	cerr << "Warning: MP_JOIN reusing four tuple of previous MP_CAPABLE: ";
	ft.display_err();
      } else if(match_index >= 0 &&
		conn_data->mp_join_subflows.exists(ft) &&
		conn_data->subflows.exists(ft)){
	int stored_index = conn_data->subflows.find(ft)->second;
	map<int, int>::iterator it = conn_data->subflow_to_connection_id.find(stored_index);
	if (it != conn_data->subflow_to_connection_id.end() &&
	    match_index != it->second){
	  cerr << match_index << " " << it->second << " Warning: MP_JOIN reusing four tuple of previous MP_JOIN: ";
	  ft.display_err();
	}
      }
      conn_data->mp_join_subflows.insert(ft);
    }
    conn_data->subflows.insert(ft);	
  }
}

void store_mp_capable_information(struct connection_data_struct * conn_data,
				  int * link_layer_offset,
				  const u_char * pkt_data,
				  unsigned int datalink_type,
				  double * timestamp){
    if (is_ipv6(datalink_type, pkt_data)){
    return;
  }

  // If IPv4, find and store both addresses
  if (is_ipv4(datalink_type, pkt_data)){
    ipv4_mp_capable_information(conn_data, link_layer_offset,
				pkt_data, timestamp);
  }
}

void ipv4_mp_capable_information(struct connection_data_struct * conn_data, int * link_layer_offset, const u_char * pkt_data, double * timestamp){
  // we only care about MP_CAPABLE here
  if (!contains_ipv4_mptcp_option(pkt_data, *link_layer_offset, MP_CAPABLE)){
    return;
  }

  FourTuple ft = get_ipv4_tcp_four_tuple(pkt_data, *link_layer_offset);
  uint8_t version = get_ipv4_mp_capable_version(pkt_data,
						*link_layer_offset);

  if (conn_data->mp_join_subflows.exists(ft)){
    cerr << "Warning: MP_CAPABLE reusing four tuple of MP_JOIN: ";
    ft.display_err();
  }
  
  if (is_ipv4_tcp_syn(pkt_data, *link_layer_offset)){
    if (!is_ipv4_tcp_ack(pkt_data, *link_layer_offset)){
      // plain SYN case, insert is true if we store the ft
      if(conn_data->mp_capable_subflows.insert(ft)){
	MPTCPConnection mp_conn(ft, *timestamp, version);
	conn_data->mptcp_connections.push_back(mp_conn);
	Plotter* plotter_ptr;
	conn_data->mptcp_plotters.push_back(plotter_ptr);
	Mapper* mp_map = new Mapper;
	conn_data->mptcp_sequence_mappings.push_back(mp_map);
	stringstream ss_filename;
	ss_filename << "connection_" << conn_data->mptcp_connections.size()-1;
	conn_data->mptcp_plotters[conn_data->mptcp_plotters.size()-1] =
	  new Plotter(ss_filename.str().c_str(),
		      ft,
		      conn_data->mptcp_connections.size()-1,
		      get_tflag(),
		      get_flag2(),
		      get_rxflag(),
		      get_ryflag());
	if (version == MP_PROTOCOL_VER_0){
	  uint64_t key = get_ipv4_mp_capable_src_key(pkt_data,
						     *link_layer_offset);
	  conn_data->mptcp_connections[conn_data->mptcp_connections.size() - 1].add_src_key(key);
	}
      } else if (version == MP_PROTOCOL_VER_0){
	map<FourTuple, int>::iterator it = conn_data->mp_capable_subflows.find(ft);
	uint64_t key = get_ipv4_mp_capable_src_key(pkt_data,
						   *link_layer_offset);
	conn_data->mptcp_connections[it->second].add_src_key(key);
      } 
    } else{
      // SYN ACK
      if (version == MP_PROTOCOL_VER_0){
	map<FourTuple, int>::iterator it = conn_data->mp_capable_subflows.find(ft);
	if (it == conn_data->mp_capable_subflows.end()){
	  return;
	}
	uint64_t key = get_ipv4_mp_capable_src_key(pkt_data,
						   *link_layer_offset);
	conn_data->mptcp_connections[it->second].add_dst_key(key);
      }
    }
  } else {
    // plain ACK
    // find connection index
    map<FourTuple, int>::iterator it = conn_data->mp_capable_subflows.find(ft);
    if (it != conn_data->mp_capable_subflows.end()){
      if (version == MP_PROTOCOL_VER_0){ // should already have stored keys
	return;
      }
      
      uint64_t send_key = get_ipv4_mp_capable_src_key(pkt_data,
						      *link_layer_offset);
      uint64_t receive_key = get_ipv4_mp_capable_dst_key(pkt_data,
							 *link_layer_offset);
      if (conn_data->mptcp_connections[it->second].has_src_key() &&
	  conn_data->mptcp_connections[it->second].get_src_key() != send_key){
	cerr << "Warning: Saw multiple MPTCP connections using ";
	cerr << "the same four tuple.";
	ft.display_err();
      }
      conn_data->mptcp_connections[it->second].add_src_key(send_key);
      conn_data->mptcp_connections[it->second].add_dst_key(receive_key);
      if (version != conn_data->mptcp_connections[it->second].get_version()){
	cerr << "Warning: Version numbers do not match for connection: ";
	cerr << it->second << "." << endl;
      }
    }
  }
}


int get_connection_id(struct connection_data_struct * conn_data,
		      int * link_layer_offset,
		      const u_char * pkt_data,
		      unsigned int datalink_type){
  // If IPv6, log an error and return. Not yet supported.
  if (is_ipv6(datalink_type, pkt_data)){
    cerr << "Warning: IPv6 support not yet implemented." << endl;
    return -1;
  }

  // If IPv4, find and store both addresses
  if (is_ipv4(datalink_type, pkt_data) ){
    return get_ipv4_connection_id(conn_data, link_layer_offset, pkt_data);
  }  
  
  return -1;
}

int get_ipv4_connection_id(struct connection_data_struct * conn_data,
			   int * link_layer_offset,
			   const u_char * pkt_data){
  if (is_ipv4_tcp(pkt_data, *link_layer_offset)){
    FourTuple ft = get_ipv4_tcp_four_tuple(pkt_data, *link_layer_offset);
    map<FourTuple, int>::iterator it = conn_data->subflows.find(ft);
    int sub_index = -1;
    if (it != conn_data->subflows.end()){
      sub_index = it->second;
    }
    map<int,int>::iterator map_it = conn_data->subflow_to_connection_id.find(sub_index);
    if (map_it != conn_data->subflow_to_connection_id.end()){
      return map_it->second; // already have a mapping
    }
    if (contains_ipv4_mptcp_option(pkt_data, *link_layer_offset, MP_CAPABLE)){
      it = conn_data->mp_capable_subflows.find(ft);//look for the index of conns
      if (it != conn_data->mp_capable_subflows.end()){
	conn_data->subflow_to_connection_id.insert(pair<int, int>(sub_index, it->second));
	return it->second;
      }
    }
    // at this point, we better have MP_JOIN or else we are missing data
    if (contains_ipv4_mptcp_option(pkt_data, *link_layer_offset, MP_JOIN)){
      uint32_t token = get_ipv4_mp_join_token(pkt_data, *link_layer_offset);
      for (unsigned int i = 0; i < conn_data->mptcp_connections.size(); i++){
	if (conn_data->mptcp_connections[i].token_matches(token)){
	  conn_data->subflow_to_connection_id.insert(pair<int,int>(sub_index, i));
	  return i;
	}
      }
    }
  }
  return -1;
}

void process_packet(struct connection_data_struct * conn_data,
		    int * link_layer_offset,
		    const u_char * pkt_data,
		    unsigned int datalink_type,
		    unsigned int index,
		    double timestamp){
  if (is_ipv6(datalink_type, pkt_data)){
    return;
  }

  // If IPv4, find and store both addresses
  if (is_ipv4(datalink_type, pkt_data)){
    ipv4_process_packet(conn_data, link_layer_offset,
			pkt_data, index, timestamp);
  }  
}

void ipv4_process_packet(struct connection_data_struct * conn_data,
			 int * link_layer_offset,
			 const u_char * pkt_data,
			 unsigned int index,
			 double timestamp){
  FourTuple ft = get_ipv4_tcp_four_tuple(pkt_data, *link_layer_offset);
  DSS dss = handle_ipv4_dss(pkt_data, *link_layer_offset);
  if (dss.is_extended_mapping()){
    conn_data->mptcp_sequence_mappings[index]->insert(dss.get_subflow_sequence_num(), dss.get_contained_dsn(), dss.get_dll());
  }
  if (dss.was_initialized_with_args()){
    if (conn_data->mptcp_plotters[index]){
      conn_data->mptcp_plotters[index]->handle_dss(dss, ft, timestamp, conn_data->subflows.get_direction(ft), &(conn_data->mptcp_connections[index]));
      conn_data->mptcp_connections[index].store_dss(dss, conn_data->subflows.get_direction(ft));
    }
  }

  conn_data->mptcp_connections[index].store_timestamp(timestamp);
  
  if (get_jflag() &&
      contains_ipv4_mptcp_option(pkt_data, *link_layer_offset, MP_JOIN)){

    conn_data->mptcp_plotters[index]->plot_mp_join(
                                   &conn_data->mptcp_connections[index],
				   timestamp,
				   conn_data->subflows.get_direction(ft),
				   ft);
  }

  if (get_aflag()){
    if (contains_ipv4_mptcp_option(pkt_data, *link_layer_offset, MP_ADD_ADDR)){
      const char text[] = "ADD_ADDR";
      conn_data->mptcp_plotters[index]->plot_tick(
                                          conn_data->subflows.get_direction(ft),
					  ft,
					  &conn_data->mptcp_connections[index],
					  timestamp,
					  text);
    }
    if (contains_ipv4_mptcp_option(pkt_data, *link_layer_offset, MP_REM_ADDR)){
      const char text[] = "REM_ADDR";
      conn_data->mptcp_plotters[index]->plot_tick(
                                          conn_data->subflows.get_direction(ft),
					  ft,
					  &conn_data->mptcp_connections[index],
					  timestamp,
					  text);
    }
  }
}

void handle_bare_tcp(struct connection_data_struct * conn_data,
		    int * link_layer_offset,
		    const u_char * pkt_data,
		    unsigned int datalink_type,
		    unsigned int index,
		    double timestamp){
  if (is_ipv6(datalink_type, pkt_data)){
    return;
  }

  // If IPv4, find and store both addresses
  if (is_ipv4(datalink_type, pkt_data) &&
      is_ipv4_tcp(pkt_data, *link_layer_offset)){
    handle_bare_ipv4_tcp(conn_data, link_layer_offset,
			 pkt_data, index, timestamp);
  }  
}

void handle_bare_ipv4_tcp(struct connection_data_struct * conn_data,
			  int * link_layer_offset,
			  const u_char * pkt_data,
			  unsigned int index,
			  double timestamp){
  if (!conn_data->mptcp_connections[index].has_dss()){
    return;
  }
  
  FourTuple ft = get_ipv4_tcp_four_tuple(pkt_data, *link_layer_offset);
  if (contains_ipv4_bare_data(pkt_data, *link_layer_offset) &&
      !contains_ipv4_mptcp_option(pkt_data, *link_layer_offset, MP_FASTCLOSE)){
    if (!g_bare_warning){
      cerr << "Warning: MPTCP data without a mapping found. Segment not ";
      cerr << "handled. Support for this is not yet implemented."<< endl;
      g_bare_warning = true;
    }
  }
}


void display_connections(vector<MPTCPConnection> * mptcp_connections){
  cout << "Number of connections: " << mptcp_connections->size() << endl;
  for (unsigned int i = 0; i < mptcp_connections->size(); i++){
    cout << "***************************************************************\n";
    cout << "Connection " << i << ":\n";
    (*mptcp_connections)[i].display();
    cout << "***************************************************************\n";
  }
}

void display_long_connections(struct connection_data_struct * conn_data){
  vector<vector<int> > subflow_ids;
  vector<FourTuple> four_tuple_values;
  for (unsigned int i = 0; i < conn_data->mptcp_connections.size(); i++){
    vector<int> ids;
    subflow_ids.push_back(ids);
  }
  map<int,int>::iterator it;
  for (int i = 0; i < conn_data->subflows.size(); i++){
    it = conn_data->subflow_to_connection_id.find(i);
    if (it != conn_data->subflow_to_connection_id.end()){
      subflow_ids[it->second].push_back(it->first);
    }
  }
  
  cout << "Number of connections: " << conn_data->mptcp_connections.size() << endl;
  
  four_tuple_values = conn_data->subflows.get_four_tuple_ids();
  
  for (unsigned int i = 0; i < conn_data->mptcp_connections.size(); i++){
    cout << "***************************************************************\n";
    cout << "Connection " << i << ":\n";
    ((conn_data->mptcp_connections))[i].display();
    cout << "###############\nSubflows in connection:\n";
    for (unsigned int j = 0; j < subflow_ids[i].size(); j++){
      four_tuple_values[subflow_ids[i][j]].display();
    }
    cout << "###############\n";
    conn_data->mptcp_connections[i].display_seq_nums_64();
    cout << "***************************************************************\n";
  }
}

void store_timestamp(const struct pcap_pkthdr * pkthdr, double * timestamp){
  (*timestamp) = pkthdr->ts.tv_sec;
  (*timestamp) += (pkthdr->ts.tv_usec / 1000000.0);
}

void clean_up_plotters(vector<Plotter*> * plotters){
  for (unsigned int i = 0; i < plotters->size(); i++){
    if ((*plotters)[i]){
      delete (*plotters)[i];
    }
  }
}

void clean_up_mappings(vector<Mapper*> * mappings){
  for (unsigned int i = 0; i < mappings->size(); i++){
    if ((*mappings)[i]){
      delete (*mappings)[i];
    }
  }
}
