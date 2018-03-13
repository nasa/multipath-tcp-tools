#include <iostream>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <pcap/sll.h>
#include <linux/if_ether.h>
#include <net/ethernet.h>
#include <string.h>

#include "layer_handlers.h"
#include "parser_utility.h"

using namespace std;




bool is_ipv4(unsigned int datalink_type, const u_char* packet){
  if (datalink_type == DLT_LINUX_SLL){
    struct sll_header *sll = (struct sll_header *)(packet);
    return (ntohs(sll->sll_protocol) == ETHERTYPE_IP);
  } else if (datalink_type == DLT_EN10MB){
    struct ethhdr *eth = (struct ethhdr *)(packet);
    return (ntohs(eth->h_proto) == ETHERTYPE_IP);
  }
  return false;
}


bool is_ipv6(unsigned int datalink_type, const u_char* packet){
  if (datalink_type == DLT_LINUX_SLL){
    struct sll_header *sll = (struct sll_header *)(packet);
    return (ntohs(sll->sll_protocol) == ETH_P_IPV6);
  } else if (datalink_type == DLT_EN10MB){
    struct ethhdr *eth = (struct ethhdr *)(packet);
    return (ntohs(eth->h_proto) == ETH_P_IPV6);
  }
  return false;
}

bool is_ipv4_tcp(const u_char * packet, const int ip_offset){
  const struct ip* ip_header;
  
  ip_header = (struct ip*)(packet + ip_offset);
  if (ip_header->ip_p == IPPROTO_TCP){
    return true;
  }
  return false;
}

bool is_tcp_syn(const u_char * packet, const int tcp_offset){
  const struct tcphdr* tcp_header;
  tcp_header = (struct tcphdr*)(packet + tcp_offset);
  return (tcp_header->syn == 0x1);
}

bool is_tcp_ack(const u_char * packet, const int tcp_offset){
  const struct tcphdr* tcp_header;
  tcp_header = (struct tcphdr*)(packet + tcp_offset);
  return (tcp_header->ack == 0x1);
}

bool is_ipv4_tcp_syn(const u_char * packet, const int ip_offset){
  const struct ip* ip_header;
  uint16_t ip_header_length = 0;
  
  ip_header = (struct ip*)(packet + ip_offset);
  if (ip_header->ip_p == IPPROTO_TCP){
    ip_header_length = (ip_header->ip_hl * 4);
    return is_tcp_syn(packet, ip_offset + ip_header_length);
  }
  return false;
}

bool is_ipv4_tcp_ack(const u_char * packet, const int ip_offset){
  const struct ip* ip_header;
  uint16_t ip_header_length = 0;
  
  ip_header = (struct ip*)(packet + ip_offset);
  if (ip_header->ip_p == IPPROTO_TCP){
    ip_header_length = (ip_header->ip_hl * 4);
    return is_tcp_ack(packet, ip_offset + ip_header_length);
  }
  return false;
}

bool is_tcp_fin(const u_char * packet, const int tcp_offset){
  const struct tcphdr* tcp_header;
  tcp_header = (struct tcphdr*)(packet + tcp_offset);
  return (tcp_header->fin == 0x1);
}

bool is_ipv4_tcp_fin(const u_char * packet, const int ip_offset){
  const struct ip* ip_header;
  uint16_t ip_header_length = 0;
  
  ip_header = (struct ip*)(packet + ip_offset);
  if (ip_header->ip_p == IPPROTO_TCP){
    ip_header_length = (ip_header->ip_hl * 4);
    return is_tcp_fin(packet, ip_offset + ip_header_length);
  }
  return false;
}

bool is_tcp_rst(const u_char * packet, const int tcp_offset){
  const struct tcphdr* tcp_header;
  tcp_header = (struct tcphdr*)(packet + tcp_offset);
  return (tcp_header->rst == 0x1);
}

bool is_ipv4_tcp_rst(const u_char * packet, const int ip_offset){
  const struct ip* ip_header;
  uint16_t ip_header_length = 0;
  
  ip_header = (struct ip*)(packet + ip_offset);
  if (ip_header->ip_p == IPPROTO_TCP){
    ip_header_length = (ip_header->ip_hl * 4);
    return is_tcp_rst(packet, ip_offset + ip_header_length);
  }
  return false;
}

FourTuple get_ipv4_tcp_four_tuple(const u_char * packet, const int ip_offset){
  const struct ip* ip_header;
  uint16_t ip_header_length = 0;
  
  ip_header = (struct ip*)(packet + ip_offset);
  if (ip_header->ip_p == IPPROTO_TCP){
    ip_header_length = (ip_header->ip_hl * 4);
    const struct tcphdr* tcp_header;
    tcp_header = (struct tcphdr*)(packet + ip_offset + ip_header_length);
    FourTuple ft = FourTuple(FOUR_TUPLE_IPV4, (uint8_t*)&ip_header->ip_src,
			     (uint8_t*)&ip_header->ip_dst,
			     (uint16_t*)&tcp_header->source,
			     (uint16_t*)&tcp_header->dest);
    return ft;
  }
  FourTuple ft;
  return ft;
}

bool contains_tcp_option(const u_char* packet, const int tcp_option_offset, const unsigned int len_options, const int target){
  const struct tcp_opt *tcp_option_header;
  uint16_t bytes_processed = 0;
  
  while (bytes_processed < len_options){
    tcp_option_header = (struct tcp_opt*)(packet + tcp_option_offset + bytes_processed);
    if (tcp_option_header->kind == TCPOPT_NOP){
      bytes_processed++;  // One byte long. No length field. Just increment.
    } else if (tcp_option_header->kind == target){
      return true;
    } else {
      // when we found a non-NOP option that doesn't match target, we have
      // to advance to the next option which is 'length' bytes away.
      bytes_processed += tcp_option_header->length;
    }
  }
  return false;
}

bool contains_mptcp_option(const u_char* packet, const int tcp_option_offset, const unsigned int len_options, const unsigned int target){
  const struct tcp_opt *tcp_option_header;
  uint16_t bytes_processed = 0;
  const struct mptcp_opt *mptcp_option_header;
  
  while (bytes_processed < len_options){
    tcp_option_header = (struct tcp_opt*)(packet + tcp_option_offset + bytes_processed);
    if (tcp_option_header->kind == TCPOPT_NOP){
      bytes_processed++;  // One byte long. No length field. Just increment.
    } else if (tcp_option_header->kind == MPTCP_OPT){
      mptcp_option_header = (struct mptcp_opt*)(packet + tcp_option_offset + bytes_processed);
      bytes_processed += tcp_option_header->length;
      if (mptcp_option_header->subtype == target){
	return true;
      }
    } else {
      bytes_processed += tcp_option_header->length;
    }
  }
  return false;
}

bool contains_ipv4_mptcp(const u_char* packet, const int ip_offset){
  const struct ip* ip_header;
  const struct tcphdr* tcp_header;
  uint16_t tcp_header_length = 0;
  uint16_t ip_header_length = 0;
  unsigned int option_offset = 0;
  unsigned int len_options = 0;
  
  ip_header = (struct ip*)(packet + ip_offset);
  if (ip_header->ip_p == IPPROTO_TCP){
    ip_header_length = (ip_header->ip_hl * 4);
    tcp_header = (struct tcphdr*)(packet + ip_offset + ip_header_length); 
    tcp_header_length = ((tcp_header->doff & 0xf0 >> 4) * 4);
  } else {
    return false;
  }
  option_offset = ip_offset + ip_header_length + sizeof(struct tcphdr);
  // TCP Header knows how long it is. Subtract off standard TCP header size
  // to get the length of the options.
  len_options = tcp_header_length - sizeof(struct tcphdr);
  return contains_tcp_option(packet, option_offset, len_options, MPTCP_OPT);
}

bool contains_ipv4_mptcp_option(const u_char* packet, const int ip_offset, const unsigned int target){
  const struct ip* ip_header;
  const struct tcphdr* tcp_header;
  uint16_t tcp_header_length = 0;
  uint16_t ip_header_length = 0;
  unsigned int option_offset = 0;
  unsigned int len_options = 0;
  
  ip_header = (struct ip*)(packet + ip_offset);
  if (ip_header->ip_p == IPPROTO_TCP){
    ip_header_length = (ip_header->ip_hl * 4);
    tcp_header = (struct tcphdr*)(packet + ip_offset + ip_header_length); 
    tcp_header_length = ((tcp_header->doff & 0xf0 >> 4) * 4);
  } else {
    return false;
  }
  option_offset = ip_offset + ip_header_length + sizeof(struct tcphdr);
  // TCP Header knows how long it is. Subtract off standard TCP header size
  // to get the length of the options.
  len_options = tcp_header_length - sizeof(struct tcphdr);
  return contains_mptcp_option(packet, option_offset, len_options, target);
}

uint8_t get_ipv4_mp_capable_version(const u_char* packet, const int ip_offset){
  const struct ip* ip_header;
  const struct tcphdr* tcp_header;
  uint16_t tcp_header_length = 0;
  uint16_t ip_header_length = 0;
  unsigned int option_offset = 0;
  unsigned int len_options = 0;
  
  ip_header = (struct ip*)(packet + ip_offset);
  if (ip_header->ip_p == IPPROTO_TCP){
    ip_header_length = (ip_header->ip_hl * 4);
    tcp_header = (struct tcphdr*)(packet + ip_offset + ip_header_length); 
    tcp_header_length = ((tcp_header->doff & 0xf0 >> 4) * 4);
  } else {
    return MP_PROTOCOL_NO_VER;
  }
  option_offset = ip_offset + ip_header_length + sizeof(struct tcphdr);
  // TCP Header knows how long it is. Subtract off standard TCP header size
  // to get the length of the options.
  len_options = tcp_header_length - sizeof(struct tcphdr);

  const struct tcp_opt *tcp_option_header;
  uint16_t bytes_processed = 0;
  const struct mptcp_opt *mptcp_option_header;
  const struct mp_capable_opt_ack *mptcp_mp_capable_opt;
  
  while (bytes_processed < len_options){
    tcp_option_header = (struct tcp_opt*)(packet + option_offset + bytes_processed);
    if (tcp_option_header->kind == TCPOPT_NOP){
      bytes_processed++;  // One byte long. No length field. Just increment.
    } else if (tcp_option_header->kind == MPTCP_OPT){
      mptcp_option_header = (struct mptcp_opt*)(tcp_option_header);
      bytes_processed += tcp_option_header->length;
      if (mptcp_option_header->subtype == MP_CAPABLE){
	mptcp_mp_capable_opt = (struct mp_capable_opt_ack*)(mptcp_option_header);
	return mptcp_mp_capable_opt->version;
      }
    } else {
      bytes_processed += tcp_option_header->length;
    }
  }
  return MP_PROTOCOL_NO_VER;
}


uint64_t get_ipv4_mp_capable_src_key(const u_char* packet, const int ip_offset){
  const struct ip* ip_header;
  const struct tcphdr* tcp_header;
  uint16_t tcp_header_length = 0;
  uint16_t ip_header_length = 0;
  unsigned int option_offset = 0;
  unsigned int len_options = 0;
  
  ip_header = (struct ip*)(packet + ip_offset);
  if (ip_header->ip_p == IPPROTO_TCP){
    ip_header_length = (ip_header->ip_hl * 4);
    tcp_header = (struct tcphdr*)(packet + ip_offset + ip_header_length); 
    tcp_header_length = ((tcp_header->doff & 0xf0 >> 4) * 4);
  } else {
    return MPTCP_NO_KEY;
  }
  option_offset = ip_offset + ip_header_length + sizeof(struct tcphdr);
  // TCP Header knows how long it is. Subtract off standard TCP header size
  // to get the length of the options.
  len_options = tcp_header_length - sizeof(struct tcphdr);

  const struct tcp_opt *tcp_option_header;
  uint16_t bytes_processed = 0;
  const struct mptcp_opt *mptcp_option_header;
  const struct mp_capable_opt_ack *mptcp_mp_capable_opt;

  while (bytes_processed < len_options){
    tcp_option_header = (struct tcp_opt*)(packet + option_offset + bytes_processed);
    if (tcp_option_header->kind == TCPOPT_NOP){
      bytes_processed++;  // One byte long. No length field. Just increment.
    } else if (tcp_option_header->kind == MPTCP_OPT){
      bytes_processed += tcp_option_header->length;
      mptcp_option_header = (struct mptcp_opt*)tcp_option_header;
      if (mptcp_option_header->subtype == MP_CAPABLE){
	mptcp_mp_capable_opt = (struct mp_capable_opt_ack*)tcp_option_header;
	return ntohll(*(uint64_t*)(&mptcp_mp_capable_opt->sender_key_upper));
      }
    } else {
      bytes_processed += tcp_option_header->length;
    }
  }
  return MPTCP_NO_KEY;
}

uint64_t get_ipv4_mp_capable_dst_key(const u_char* packet, const int ip_offset){
  const struct ip* ip_header;
  const struct tcphdr* tcp_header;
  uint16_t tcp_header_length = 0;
  uint16_t ip_header_length = 0;
  unsigned int option_offset = 0;
  unsigned int len_options = 0;
  
  ip_header = (struct ip*)(packet + ip_offset);
  if (ip_header->ip_p == IPPROTO_TCP){
    ip_header_length = (ip_header->ip_hl * 4);
    tcp_header = (struct tcphdr*)(packet + ip_offset + ip_header_length); 
    tcp_header_length = ((tcp_header->doff & 0xf0 >> 4) * 4);
  } else {
    return MPTCP_NO_KEY;
  }
  option_offset = ip_offset + ip_header_length + sizeof(struct tcphdr);
  // TCP Header knows how long it is. Subtract off standard TCP header size
  // to get the length of the options.
  len_options = tcp_header_length - sizeof(struct tcphdr);

  const struct tcp_opt *tcp_option_header;
  uint16_t bytes_processed = 0;
  const struct mptcp_opt *mptcp_option_header;
  const struct mp_capable_opt_ack *mptcp_mp_capable_opt;

  while (bytes_processed < len_options){
    tcp_option_header = (struct tcp_opt*)(packet + option_offset + bytes_processed);
    if (tcp_option_header->kind == TCPOPT_NOP){
      bytes_processed++;  // One byte long. No length field. Just increment.
    } else if (tcp_option_header->kind == MPTCP_OPT){
      bytes_processed += tcp_option_header->length;
      mptcp_option_header = (struct mptcp_opt*)tcp_option_header;
      if (mptcp_option_header->subtype == MP_CAPABLE){
	mptcp_mp_capable_opt = (struct mp_capable_opt_ack*)tcp_option_header;
	return ntohll(*(uint64_t*)(&mptcp_mp_capable_opt->receiver_key_upper));
      }
    } else {
      bytes_processed += tcp_option_header->length;
    }
  }
  return MPTCP_NO_KEY;
}



uint32_t get_ipv4_mp_join_token(const u_char* packet, const int ip_offset){
  const struct ip* ip_header;
  const struct tcphdr* tcp_header;
  uint16_t tcp_header_length = 0;
  uint16_t ip_header_length = 0;
  unsigned int option_offset = 0;
  unsigned int len_options = 0;
  
  ip_header = (struct ip*)(packet + ip_offset);
  if (ip_header->ip_p == IPPROTO_TCP){
    ip_header_length = (ip_header->ip_hl * 4);
    tcp_header = (struct tcphdr*)(packet + ip_offset + ip_header_length); 
    tcp_header_length = ((tcp_header->doff & 0xf0 >> 4) * 4);
  } else {
    return MPTCP_NO_KEY;
  }
  option_offset = ip_offset + ip_header_length + sizeof(struct tcphdr);
  // TCP Header knows how long it is. Subtract off standard TCP header size
  // to get the length of the options.
  len_options = tcp_header_length - sizeof(struct tcphdr);
  
  const struct tcp_opt *tcp_option_header;
  uint16_t bytes_processed = 0;
  const struct mptcp_opt *mptcp_option_header;
  const struct mp_join_opt_v0_syn *mptcp_join_header;
  
  while (bytes_processed < len_options){
    tcp_option_header = (struct tcp_opt*)(packet + option_offset + bytes_processed);
    if (tcp_option_header->kind == TCPOPT_NOP){
      bytes_processed++;  // One byte long. No length field. Just increment.
    } else if (tcp_option_header->kind == MPTCP_OPT){
      mptcp_option_header = (struct mptcp_opt*)(tcp_option_header);
      bytes_processed += tcp_option_header->length;
      if (mptcp_option_header->subtype == MP_JOIN){
	mptcp_join_header = (struct mp_join_opt_v0_syn*)(mptcp_option_header);
	return ntohl(mptcp_join_header->token);
      }
    } else {
      bytes_processed += tcp_option_header->length;
    }
  }
  return MPTCP_NO_KEY;
}

DSS handle_ipv4_dss(const u_char * packet, const unsigned int ip_offset){
  const struct ip* ip_header;
  const struct tcphdr* tcp_header;
  uint16_t tcp_header_length = 0;
  uint16_t ip_header_length = 0;
  uint16_t ip_len;
  uint16_t payload_length = 0;
  
  ip_header = (struct ip*)(packet + ip_offset);
  ip_len = ntohs(ip_header->ip_len);
  if (ip_header->ip_p == IPPROTO_TCP){
    ip_header_length = (ip_header->ip_hl * 4);
    tcp_header = (struct tcphdr*)(packet + ip_offset + ip_header_length); 
    tcp_header_length = ((tcp_header->doff & 0xf0 >> 4) * 4);
    
    const unsigned int first_option_offset = ip_offset + ip_header_length + sizeof(struct tcphdr);
    const struct tcp_opt *tcp_option_header;
    uint16_t bytes_processed = 0;
    uint16_t len_options = tcp_header_length - sizeof(struct tcphdr);
    const struct base_dss_option *mp_dss_hdr;  // start of DSS option is always
                                               // the same. total size varies.
    payload_length = (ip_len - ip_header_length - tcp_header_length);	
    
    while (bytes_processed < len_options){
      tcp_option_header = (struct tcp_opt*)(packet + first_option_offset + bytes_processed);
      if (tcp_option_header->kind == TCPOPT_NOP){ // NOP is 1-byte
        bytes_processed++;
      } else if (tcp_option_header->kind == MPTCP_OPT){
        mp_dss_hdr = (struct base_dss_option*)(packet + first_option_offset + bytes_processed);
        if (mp_dss_hdr->subtype == MP_DSS){
          DSS mydss((packet + first_option_offset + bytes_processed), payload_length);
          return mydss;  // DSS object containing relevant fields set
        }
        bytes_processed += mp_dss_hdr->length;  // other MPTCP option
      } else {
        bytes_processed += tcp_option_header->length; // non-MPTCP TCP option
      }
    }
    DSS noDss;
    noDss.set_payload_length(payload_length);
    return noDss;
  }
  DSS noDss;
  return noDss; // Calling was_initialized_with_args() for a DSS object
}               // will show whether an object is empty or not.

bool contains_ipv4_bare_data(const u_char * packet,
			     const unsigned int ip_offset){
  DSS test_dss = handle_ipv4_dss(packet, ip_offset);
  if (!test_dss.has_dsn() && test_dss.get_payload_length() > 0){
    return true;
  }
  return false;
}
