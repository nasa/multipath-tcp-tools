#include <iostream>
#include "conn_crunch_processing.h"
#include "layer_handlers.h"
#include "parser_utility.h"
#include "subflow.h"

/*
struct conn_cruncher_data_struct{
  ConnectionMap four_tuples;
  std::vector<Subflow> subflows;
  std::vector<int> four_tuple_to_subflow;
  MPTCPConnection * connection;
  Subflow orig_dir_subflow;
  Subflow remote_dir_subflow;
};
*/

void update_found_mapping(struct conn_cruncher_data_struct * data_struct,
			  FourTuple * ft,
			  double timestamp,
			  const u_char * packet,
			  const int ip_offset){
  int subflow_id = data_struct->four_tuples.find(*ft)->second;
  
  if (contains_ipv4_mptcp_option(packet, ip_offset, MP_CAPABLE)){
    uint64_t packet_key;
    uint64_t stored_key;
    if (is_ipv4_tcp_syn(packet, ip_offset)){
      //  MP_CAPABLE SYN
      //    does this key match stored key? Y: Return. N: ERROR!
      packet_key = get_ipv4_mp_capable_src_key(packet, ip_offset);
      stored_key = data_struct->subflows[data_struct->four_tuple_to_subflow[subflow_id]].get_key();
      if (!is_ipv4_tcp_ack(packet, ip_offset)){
	if (packet_key != stored_key){
	  std::cerr << "Warning: Multiple MP_CAPABLE subflows in this file. ";
	  std::cerr << "Program requires a single MPTCP connection per file.";
	  std::cerr << std::endl;
	}
	return;
      } else {     // ack check
	data_struct->connection->add_dst_key(packet_key);
      }            // not an ack check
    }  // syn check
  }  // mp_capable check
  else if(contains_ipv4_mptcp_option(packet, ip_offset, MP_JOIN) && 
	  is_ipv4_tcp_syn(packet, ip_offset) &&
	  !is_ipv4_tcp_ack(packet, ip_offset)){
    uint32_t packet_token = get_ipv4_mp_join_token(packet, ip_offset);
    uint32_t stored_token = data_struct->subflows[data_struct->four_tuple_to_subflow[subflow_id]].get_token();
    if (packet_token == stored_token){
      return;
    }
    std::cerr << "Warning: Reuse of four tuple ";
    std::cerr << ft->get_src_string() << std::endl;
    Subflow new_subflow(MP_SUBFLOW_TYPE_JOIN, timestamp, *ft);
    FourTuple ft_rev = (*ft);
    ft_rev.reverse();
    Subflow rev_subflow(MP_SUBFLOW_TYPE_JOIN, MP_UNINITIALIZED_TS, ft_rev);
    new_subflow.store_token(packet_token);
    data_struct->subflows.push_back(new_subflow);
    data_struct->reverse_subflows.push_back(rev_subflow);
    data_struct->four_tuple_to_subflow[subflow_id] = data_struct->four_tuples.size() - 1;
  }  // bare SYN MP_JOIN check
}

void create_new_mapping(struct conn_cruncher_data_struct * data_struct,
			FourTuple * ft,
			double timestamp,
			const u_char * packet,
			const int ip_offset){
  data_struct->four_tuples.insert(*ft);
  data_struct->four_tuple_to_subflow.push_back(-1);
  int four_tuple_id = data_struct->four_tuples.find(*ft)->second;
  
  if (is_ipv4_tcp_syn(packet, ip_offset) &&
      !is_ipv4_tcp_ack(packet, ip_offset)) {
    if (contains_ipv4_mptcp_option(packet, ip_offset, MP_CAPABLE)){
      uint64_t packet_key = get_ipv4_mp_capable_src_key(packet, ip_offset);
      Subflow new_subflow(MP_SUBFLOW_TYPE_CAPABLE, timestamp, *ft);
      FourTuple ft_rev = (*ft);
      ft_rev.reverse();
      Subflow rev_subflow(MP_SUBFLOW_TYPE_CAPABLE, MP_UNINITIALIZED_TS, ft_rev);
      new_subflow.set_direction(PKT_SRC_SENT);
      rev_subflow.set_direction(PKT_DST_SENT);
      
      new_subflow.store_key(packet_key);
      data_struct->subflows.push_back(new_subflow);
      data_struct->reverse_subflows.push_back(rev_subflow);
      data_struct->four_tuple_to_subflow[four_tuple_id] = data_struct->four_tuples.size() - 1;
      if (data_struct->connection == NULL){
	data_struct->connection = new MPTCPConnection(*ft, timestamp,
						      MP_PROTOCOL_VER_0);
	data_struct->connection->add_src_key(packet_key);
      }
    } // mp_capable check
    else if (contains_ipv4_mptcp_option(packet, ip_offset, MP_JOIN)){
      uint32_t packet_token = get_ipv4_mp_join_token(packet, ip_offset);
            
      Subflow new_subflow(MP_SUBFLOW_TYPE_JOIN, timestamp, *ft);
      FourTuple ft_rev = (*ft);
      ft_rev.reverse();
      Subflow rev_subflow(MP_SUBFLOW_TYPE_JOIN, MP_UNINITIALIZED_TS, ft_rev);
      new_subflow.store_token(packet_token);

      if (data_struct->connection->src_token_matches(packet_token)){
	new_subflow.set_direction(PKT_DST_SENT);
	rev_subflow.set_direction(PKT_SRC_SENT);
      } else if (data_struct->connection->dst_token_matches(packet_token)){
	new_subflow.set_direction(PKT_SRC_SENT);
	rev_subflow.set_direction(PKT_DST_SENT);
      } else {
	std::cerr << "Warning: Token does not match either direction!" << std::endl;
	return;
      }
      data_struct->subflows.push_back(new_subflow);
      data_struct->reverse_subflows.push_back(rev_subflow);
      

      data_struct->four_tuple_to_subflow[four_tuple_id] = data_struct->four_tuples.size() - 1;
    } // mp_join check
  } // bare SYN check
}


void subflow_packet_handler(struct conn_cruncher_data_struct * data_struct,
			    struct packet_handler_struct * pkt_struct){
  if (pkt_struct->subflow == NULL || pkt_struct->direction == PKT_UNKNOWN_DIR){
    return;
  }
  
  pkt_struct->subflow->store_packet_time(*(pkt_struct->timestamp));
  DSS dss = handle_ipv4_dss(pkt_struct->pktdata,
			    (*(pkt_struct->link_layer_offset)));
  pkt_struct->subflow->increment_packet_count();
  pkt_struct->subflow->increase_payload_byte_count(dss.get_payload_length());

  if (dss.is_data_fin()){
    pkt_struct->subflow->store_datafin_time(*(pkt_struct->timestamp));
  }
  
  if (dss.get_payload_length() > 0){
    pkt_struct->subflow->store_data_times(*(pkt_struct->timestamp));
    pkt_struct->subflow->increment_data_packet_count();
  }
  if (is_ipv4_tcp_fin(pkt_struct->pktdata,
		      (*(pkt_struct->link_layer_offset))) ||
      is_ipv4_tcp_rst(pkt_struct->pktdata,
		      (*(pkt_struct->link_layer_offset)))){
    pkt_struct->subflow->store_fin_rst_time(*(pkt_struct->timestamp));
  }

  if (contains_ipv4_mptcp_option(pkt_struct->pktdata,
				 (*(pkt_struct->link_layer_offset)),
				 MP_FASTCLOSE)){
    pkt_struct->subflow->store_fastclose_time(*(pkt_struct->timestamp));
  }
}

void connection_packet_handler(struct conn_cruncher_data_struct * data_struct,
			       struct packet_handler_struct * pkt_struct){
  if (pkt_struct->direction == PKT_UNKNOWN_DIR){
    return;
  }

  DSS dss = handle_ipv4_dss(pkt_struct->pktdata,
			    (*(pkt_struct->link_layer_offset)));
  data_struct->connection->store_dss(dss, pkt_struct->direction);

  Subflow * dummy_subflow = NULL;
  
  if (pkt_struct->direction == PKT_SRC_SENT){
    dummy_subflow = &data_struct->orig_dir_subflow;
  } else if (pkt_struct->direction == PKT_DST_SENT){
    dummy_subflow = &data_struct->remote_dir_subflow;
  }
  
  dummy_subflow->store_packet_time(*(pkt_struct->timestamp));
  dummy_subflow->increment_packet_count();
  dummy_subflow->increase_payload_byte_count(dss.get_payload_length());
  
  if (dss.is_data_fin()){
    dummy_subflow->store_datafin_time(*(pkt_struct->timestamp));
  }
  
  if (dss.get_payload_length() > 0){
    dummy_subflow->store_data_times(*(pkt_struct->timestamp));
    dummy_subflow->increment_data_packet_count();
  }
  if (is_ipv4_tcp_fin(pkt_struct->pktdata,
		      (*(pkt_struct->link_layer_offset))) ||
      is_ipv4_tcp_rst(pkt_struct->pktdata,
		      (*(pkt_struct->link_layer_offset)))){
    dummy_subflow->store_fin_rst_time(*(pkt_struct->timestamp));
  }

  if (contains_ipv4_mptcp_option(pkt_struct->pktdata,
				 (*(pkt_struct->link_layer_offset)),
				 MP_FASTCLOSE)){
    dummy_subflow->store_fastclose_time(*(pkt_struct->timestamp));
  }
}

void clear_subflow_packet(struct packet_handler_struct * pkt_struct){  
  pkt_struct->subflow = NULL;
  pkt_struct->pktdata = NULL;
  pkt_struct->link_layer_offset = NULL;
  pkt_struct->timestamp = NULL;
  pkt_struct->direction = PKT_UNKNOWN_DIR;
}

void initialize_cruncher_data(struct conn_cruncher_data_struct * data_struct){
  data_struct->connection = NULL;
}

void cleanup_cruncher_data(struct conn_cruncher_data_struct * data_struct){
  if (data_struct->connection != NULL){
    delete data_struct->connection;
  }
}

void display_subflows(struct conn_cruncher_data_struct * data_struct){
  for (unsigned int i = 0; i < data_struct->subflows.size(); i++){
    std::cout << "Subflow " << i << ":\n";
    if (data_struct->subflows[i].get_direction() == PKT_SRC_SENT){
      data_struct->subflows[i].display();
      data_struct->reverse_subflows[i].display();
    } else if (data_struct->subflows[i].get_direction() == PKT_DST_SENT){
      data_struct->reverse_subflows[i].display();
      data_struct->subflows[i].display();
    }
  }
}
