//
// mptcp_connection.h
//
// Class to store information about an MPTCP connection, its subflows, and
// relevant key and token information.
//
#ifndef __MPTCPPARSER_MPTCP_CONNECTION_H
#define __MPTCPPARSER_MPTCP_CONNECTION_H

#include <vector>
#include "four_tuple.h"
#include "dss.h"

class MPTCPConnection{
 public:
  // Initialize with the four tuple of the TCP SYN packet that contains the
  // MP_CAPABLE option. Also pass along the 64-bit key from that option.
  // Relevant tokens and sequence numbers will be calculated and stored.
  MPTCPConnection(FourTuple st, double timestamp, uint8_t ver);
  ~MPTCPConnection(){}
  
  void display();

  void display_seq_nums_64();

  // Store d_key in dst_key. Assume this key comes from an MP_CAPABLE option
  // carried by a SYN/ACK packet.
  void add_dst_key(uint64_t d_key);

  void add_src_key(uint64_t s_key);

  uint64_t get_src_key() const {return src_key;}
  uint64_t get_dst_key() const {return dst_key;}

  // Return true if tok matches the src_token or dst_token of the connection
  bool token_matches(uint32_t tok);
  bool src_token_matches(uint32_t tok);
  bool dst_token_matches(uint32_t tok);

  // MPTCP Data sequence numbers are 64-bits long, but hosts sending slowly
  // enough may only send the lower 32-bits in their options. We store
  // the topmost bits in 64-bit numbers (although this could be accomplished
  // with 32-bit numbers. should change).
  //
  // Likewise, the data sequence number can be represented as the full
  // 64-bit value or just as its lower 32-bits, so a function that gets
  // each representation is handy.
  uint64_t get_src_top_most_sequence_bits(){return src_top_most_sequence_bits;}
  uint64_t get_dst_top_most_sequence_bits(){return dst_top_most_sequence_bits;}
  uint64_t get_src_initial_sequence_number64(){return src_initial_sequence_number;}
  uint64_t get_dst_initial_sequence_number64(){return dst_initial_sequence_number;}
  uint32_t get_src_initial_sequence_number32(){return src_initial_sequence_number & 0xffffffff;}
  uint32_t get_dst_initial_sequence_number32(){return dst_initial_sequence_number & 0xffffffff;}

  // increment bit number 32
  void increment_src_topmost(){src_top_most_sequence_bits += 0x100000000;} 
  void increment_dst_topmost(){dst_top_most_sequence_bits += 0x100000000;}

  void store_timestamp(double new_timestamp){last_timestamp = new_timestamp;}

  void store_dss(DSS dss, int direction);

  double get_initial_timestamp(){return initial_timestamp;}
  double get_last_timestamp(){return last_timestamp;}
  uint64_t get_src_last_seq64(){return src_last_seq | get_src_top_most_sequence_bits();}
  uint64_t get_dst_last_seq64(){return dst_last_seq | get_dst_top_most_sequence_bits();}

  uint32_t get_src_last_seq32(){return src_last_seq & 0xffffffff;}
  uint32_t get_dst_last_seq32(){return dst_last_seq & 0xffffffff;}

  void store_src_seq(uint64_t new_seq);
  void store_dst_seq(uint64_t new_seq);

  FourTuple get_source_tuple(){return source_tuple;}

  uint8_t get_version() const {return version;}
  bool has_src_key(){ return (src_key > 0); }

  bool has_dss();

  uint32_t get_src_token(){return src_token;}
  uint32_t get_dst_token(){return dst_token;}
  
 private:
  FourTuple source_tuple;

  uint8_t version;
  
  uint64_t src_key;  // From:
  uint64_t dst_key;  // MP_CAPABLE options

  uint32_t src_token;                   // Calculated from:
  uint32_t dst_token;                   // src_key and dst_key
  uint64_t src_initial_sequence_number;
  uint64_t src_top_most_sequence_bits;
  uint64_t dst_initial_sequence_number;
  uint64_t dst_top_most_sequence_bits;

  double initial_timestamp;
  double last_timestamp;

  uint64_t src_last_seq;
  uint64_t dst_last_seq;

  bool sent_dss;
};

#endif
