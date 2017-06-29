#include <stdint.h>
#include <iostream>

#include "split_processing.h"
#include "layer_handlers.h"

using namespace std;

/*
struct splitter_data_struct{
  ConnectionMap four_tuples;
  std::vector<MPTCPConnection> connections;
  std::vector<int> four_tuple_to_connection;
};
 */

void update_found_mapping(struct splitter_data_struct * data_struct,
			  FourTuple * ft,
			  double timestamp,
			  const u_char * packet,
			  const int ip_offset){
  int connection_id = data_struct->four_tuples.find(*ft)->second;
  
  if (contains_ipv4_mptcp_option(packet, ip_offset, MP_CAPABLE)){
    uint64_t packet_key;
    uint64_t stored_key;
    if (is_ipv4_tcp_syn(packet, ip_offset)){
      if (!is_ipv4_tcp_ack(packet, ip_offset)){
	//  MP_CAPABLE SYN
	//    does this key match stored key? Y: Return N: update mapping
	packet_key = get_ipv4_mp_capable_src_key(packet, ip_offset);
	stored_key = data_struct->connections[data_struct->four_tuple_to_connection[connection_id]].get_src_key();
	if (packet_key == stored_key){
	  return;
	}
	MPTCPConnection new_conn(*ft, timestamp, MP_PROTOCOL_VER_0);
	new_conn.add_src_key(packet_key);
	data_struct->connections.push_back(new_conn);
	pair<double, double> times(-1.0, 0.0);
	data_struct->durations.push_back(times);
	data_struct->four_tuple_to_connection[connection_id] = data_struct->connections.size() - 1;
      } else {  // not an ack check
	//  MP_CAPABLE SYN/ACK
	packet_key = get_ipv4_mp_capable_src_key(packet, ip_offset);
	data_struct->connections[data_struct->four_tuple_to_connection[connection_id]].add_dst_key(packet_key);
	return;
      }  // ack check
    }  // syn check
  }  // mp_capable check
  else if(contains_ipv4_mptcp_option(packet, ip_offset, MP_JOIN) && 
	  is_ipv4_tcp_syn(packet, ip_offset) &&
	  !is_ipv4_tcp_ack(packet, ip_offset)){
    //  MP_JOIN SYN
    //    do we find this token matches a stored mptcp connection token?
    //    Y: update mapping
    //    N: update error mapping
    uint32_t packet_token = get_ipv4_mp_join_token(packet, ip_offset);
    for (unsigned int i = 0; i < data_struct->connections.size(); i++){
      if (data_struct->connections[i].token_matches(packet_token)){
	data_struct->four_tuple_to_connection[connection_id] = i;
	return;
      }  // token check
    }  // for loop through connections
    data_struct->four_tuple_to_connection[connection_id] = -1;
  }  // bare SYN MP_JOIN check
} 


void create_new_mapping(struct splitter_data_struct * data_struct,
			FourTuple * ft,
			double timestamp,
			const u_char * packet,
			const int ip_offset){
  data_struct->four_tuples.insert(*ft);
  data_struct->four_tuple_to_connection.push_back(-1);
  int connection_id = data_struct->four_tuples.find(*ft)->second;
  
  if (is_ipv4_tcp_syn(packet, ip_offset) &&
      !is_ipv4_tcp_ack(packet, ip_offset)) {
    if (contains_ipv4_mptcp_option(packet, ip_offset, MP_CAPABLE)){
      uint64_t packet_key = get_ipv4_mp_capable_src_key(packet, ip_offset);
      MPTCPConnection new_conn(*ft, timestamp, MP_PROTOCOL_VER_0);
      new_conn.add_src_key(packet_key);
      data_struct->connections.push_back(new_conn);
      pair<double, double> times(-1.0, 0.0);
      data_struct->durations.push_back(times);
      data_struct->four_tuple_to_connection[connection_id] = data_struct->connections.size() - 1;
    } // mp_capable check
    else if (contains_ipv4_mptcp_option(packet, ip_offset, MP_JOIN)){
      uint32_t packet_token = get_ipv4_mp_join_token(packet, ip_offset);
      for (unsigned int i = 0; i < data_struct->connections.size(); i++){
	if (data_struct->connections[i].token_matches(packet_token)){
	  data_struct->four_tuple_to_connection[connection_id] = i;
	  return;
	}  // token check
      }  // for loop through connections
    } // mp_join check
  } // bare SYN check
}

void update_timestamps(struct splitter_data_struct * data_struct,
		       const int & connection_id,
		       const double & timestamp){
  if (connection_id < 0){
    return;
  } else if(connection_id >= (int)data_struct->durations.size()){
    cout << "Warning: Tried to reference a connection that is out of range: ";
    cout << connection_id << ". Only " << data_struct->durations.size();
    cout << " connections are stored." << endl;
    return;
  }
  if (data_struct->durations[connection_id].first < 0.0 ||
      data_struct->durations[connection_id].first > timestamp){
    data_struct->durations[connection_id].first = timestamp;
  }
  if (data_struct->durations[connection_id].second < timestamp){
    data_struct->durations[connection_id].second = timestamp;
  }
}
