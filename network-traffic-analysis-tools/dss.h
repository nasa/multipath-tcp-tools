// 
// dss.h
//
// Class and struct definitions for dealing with the DSS option in
// an MPTCP packet.
// 
// 
#ifndef __MPTCPPARSER_DSS_H
#define __MPTCPPARSER_DSS_H

#include <stdint.h>

// ENDIANNESS IGNORED FOR NOW!
// Probably want to put a check here so we are compatible with other
// types of machines. Otherwise, bits may be out of order.
//
// DSS format from: tools.ietf.org/html/rfc6824
struct base_dss_option{
  uint8_t kind;
  uint8_t length;
  uint8_t pad1:4;
  uint8_t subtype:4;
  uint8_t ack:1;
  uint8_t big_ack:1;
  uint8_t dsn:1;
  uint8_t big_dsn:1;
  uint8_t data_fin:1;
  uint8_t pad2:3;  
};

class DSS{
 public:
  // zero everything out. initialized_with_args = false
  DSS();

  // Parse and store values assuming a DSS option starts at the location
  // pointed to by option_start. initialized_with_args = true
  DSS(const unsigned char * option_start, uint16_t payload_len);

  // Self-explanatory functions:
  void display();
  bool was_initialized_with_args(){return initialized_with_args;}

  bool has_ack(){return option_header.ack == 1;}
  bool has_dsn(){return option_header.dsn == 1;}
  bool has_big_ack(){return option_header.big_ack == 1;}
  bool has_big_dsn(){return option_header.big_dsn == 1;}
  bool is_data_fin(){return option_header.data_fin == 1;}

  bool contains_payload(){return payload_length > 0;}
  bool is_extended_mapping(){
    if (is_data_fin() && data_level_length > 1){
      return (data_level_length - 1) > payload_length;
    } else if (data_level_length == 1){
      return false;
    }
    return (data_level_length > payload_length);
  }
  
  uint32_t get_dsn(){return data_sequence_num;}
  uint64_t get_big_dsn(){return big_data_sequence_num;}
  uint64_t get_contained_dsn(){
    if (option_header.big_dsn == 1){
      return big_data_sequence_num;
    } else if (option_header.dsn == 1){
      return data_sequence_num;
    }
    return 0;
  }

  uint32_t get_ack(){return data_ack;}
  uint64_t get_big_ack(){return big_data_ack;}

  uint16_t get_dll(){return data_level_length;}
  uint16_t get_payload_length(){return payload_length;}

  uint32_t get_subflow_sequence_num(){return subflow_sequence_num;}

  void set_payload_length(uint16_t payload_len){payload_length = payload_len;}
  
 private:
  struct base_dss_option option_header;

  // Not all fields will be used for any given DSS option. Perhaps we
  // optimize this in the future if problematic.
  uint32_t data_ack;
  uint32_t data_sequence_num;
  uint64_t big_data_ack;
  uint64_t big_data_sequence_num;
  uint32_t subflow_sequence_num;
  uint16_t data_level_length;
  uint16_t checksum;
  bool initialized_with_args;

  uint16_t payload_length;
};

#endif
