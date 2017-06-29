#ifndef __MPTCPPARSER_SUBFLOW_H
#define __MPTCPPARSER_SUBFLOW_H

#include <stdint.h>
#include <string>
#include "four_tuple.h"

#define MP_SUBFLOW_TYPE_NONE -1
#define MP_SUBFLOW_TYPE_CAPABLE 0
#define MP_SUBFLOW_TYPE_JOIN 1
#define MP_UNINITIALIZED_TS -1.0

#define MP_UNINITIALIZED_KEY 0
#define MP_UNINITIALIZED_TOKEN 0

std::string get_timestamp_display(double timestamp);
void display_timestamp(double timestamp);


class Subflow{
 public:
  Subflow();
  Subflow(int subflow_type, double timestamp);
  Subflow(int subflow_type, double timestamp, FourTuple ft);

  void store_key(uint64_t key);
  void store_token(uint32_t tok);

  void increment_packet_count();
  void increment_data_packet_count();

  void increase_payload_byte_count(uint16_t bytes);

  void store_packet_time(double timestamp);

  void store_data_times(double timestamp);
  void store_fin_rst_time(double timestamp);
  void store_fastclose_time(double timestamp);
  void store_datafin_time(double timestamp);

  FourTuple get_ft(){return src_four_tuple;}
    
  uint64_t get_key();
  uint32_t get_token();

  void set_direction(int d);
  int get_direction();

  std::string get_short_string() const;
  
  void display() const;

 private:

  void initialize();
  
  int direction;
  
  double first_timestamp;
  double last_timestamp;
  
  double first_data_timestamp;
  double last_data_timestamp;
  double first_fin_rst_timestamp;
  int type;

  uint64_t mp_capable_key;
  uint32_t mp_join_token;

  unsigned int packet_count;
  unsigned int payload_byte_count;
  unsigned int data_packet_count;

  double first_fastclose_timestamp;
  double last_fastclose_timestamp;

  double first_datafin_timestamp;
  double last_datafin_timestamp;
  
  FourTuple src_four_tuple;
};

#endif
