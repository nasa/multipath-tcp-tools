#include <iostream>
#include <sstream>
#include "subflow.h"
#include "parser_utility.h"

using namespace std;

string get_timestamp_display(double timestamp){
  stringstream string_builder;
  string_builder << fixed;
  if (timestamp == MP_UNINITIALIZED_TS){
    string_builder << "- ";
  } else{
    string_builder << timestamp << " ";
  }
  return string_builder.str();
}

void display_timestamp(double timestamp){
  cout << get_timestamp_display(timestamp);
}

Subflow::Subflow(){
  initialize();
}

Subflow::Subflow(int subflow_type, double timestamp){
  initialize();
  
  type = subflow_type;
  first_timestamp = timestamp;
  last_timestamp = timestamp;
}

Subflow::Subflow(int subflow_type, double timestamp, FourTuple ft){
  initialize();
  
  type = subflow_type;
  first_timestamp = timestamp;
  last_timestamp = timestamp;
  src_four_tuple = ft;
}

void Subflow::initialize(){
  direction = PKT_UNKNOWN_DIR;
  
  first_timestamp = MP_UNINITIALIZED_TS;
  last_timestamp = MP_UNINITIALIZED_TS;
  
  first_data_timestamp = MP_UNINITIALIZED_TS;
  last_data_timestamp = MP_UNINITIALIZED_TS;
  first_fin_rst_timestamp = MP_UNINITIALIZED_TS;  
  type = MP_SUBFLOW_TYPE_NONE;

  mp_capable_key = MP_UNINITIALIZED_KEY;
  mp_join_token = MP_UNINITIALIZED_TOKEN;

  packet_count = 0;
  payload_byte_count = 0;
  data_packet_count = 0;
  
  first_fastclose_timestamp = MP_UNINITIALIZED_TS;
  last_fastclose_timestamp = MP_UNINITIALIZED_TS;
  
  first_datafin_timestamp = MP_UNINITIALIZED_TS;
  last_datafin_timestamp = MP_UNINITIALIZED_TS;
}

void Subflow::set_direction(int d){
  if (d == PKT_SRC_SENT || d == PKT_DST_SENT){
    direction = d;
  }
}

int Subflow::get_direction(){
  return direction;
}

void Subflow::store_key(uint64_t key){
  mp_capable_key = key;
}

void Subflow::store_token(uint32_t tok){
  mp_join_token = tok;
}

void Subflow::increment_packet_count(){
  packet_count++;
}

void Subflow::increment_data_packet_count(){
  data_packet_count++;
}

void Subflow::increase_payload_byte_count(uint16_t bytes){
  payload_byte_count += bytes;
}

void Subflow::store_packet_time(double timestamp){
  if (first_timestamp == MP_UNINITIALIZED_TS){
    first_timestamp = timestamp;
  }
  if (timestamp > last_timestamp){
    last_timestamp = timestamp;
  }
}

void Subflow::store_data_times(double timestamp){
  if (first_data_timestamp == MP_UNINITIALIZED_TS){
    first_data_timestamp = timestamp;
  }
  if (timestamp > last_data_timestamp){
    last_data_timestamp = timestamp;
  }
}

void Subflow::store_fin_rst_time(double timestamp){
  if (first_fin_rst_timestamp == MP_UNINITIALIZED_TS){
    first_fin_rst_timestamp = timestamp;
  }  
}

void Subflow::store_fastclose_time(double timestamp){
  if (first_fastclose_timestamp == MP_UNINITIALIZED_TS){
    first_fastclose_timestamp = timestamp;
  }
  if (timestamp > last_fastclose_timestamp){
    last_fastclose_timestamp = timestamp;
  }
}

void Subflow::store_datafin_time(double timestamp){
  if (first_datafin_timestamp == MP_UNINITIALIZED_TS){
    first_datafin_timestamp = timestamp;
  }
  if (timestamp > last_datafin_timestamp){
    last_datafin_timestamp = timestamp;
  }
}

uint64_t Subflow::get_key(){
  return mp_capable_key;
}

uint32_t Subflow::get_token(){
  return mp_join_token;
}

string Subflow::get_short_string() const{
  stringstream string_builder;
  string_builder << fixed << "first_timestamp: ";
  string_builder << get_timestamp_display(first_timestamp);

  string_builder << fixed << "last_timestamp: ";
  string_builder << get_timestamp_display(last_timestamp);
  
  string_builder << "first_data_timestamp: ";
  string_builder << get_timestamp_display(first_data_timestamp);

  string_builder << "last_data_timestamp: ";
  string_builder << get_timestamp_display(last_data_timestamp);

  string_builder << "first_fastclose_timestamp: ";
  string_builder << get_timestamp_display(first_fastclose_timestamp);

  string_builder << "last_fastclose_timestamp: ";
  string_builder << get_timestamp_display(last_fastclose_timestamp);

  string_builder << "first_datafin_timestamp: ";
  string_builder << get_timestamp_display(first_datafin_timestamp);

  string_builder << "last_datafin_timestamp: ";
  string_builder << get_timestamp_display(last_datafin_timestamp);

  string_builder << "packet_count: " << packet_count << " ";
  string_builder << "data_packet_count: " << data_packet_count << " ";
  string_builder << "payload_byte_count: " << payload_byte_count;
  return string_builder.str();
}

void Subflow::display() const{
  cout << src_four_tuple.get_src_string() << " ";
  cout << "Type: ";
  switch(type){
  case MP_SUBFLOW_TYPE_CAPABLE:
    cout << "MP_CAPABLE ";
    break;
  case MP_SUBFLOW_TYPE_JOIN:
    cout << "MP_JOIN ";
    break;
  default:
    cout << "Unknown ";
    break;
  }
  cout << fixed << "first_timestamp: ";
  display_timestamp(first_timestamp);

  cout << fixed << "last_timestamp: ";
  display_timestamp(last_timestamp);
  
  cout << "first_data_timestamp: ";
  display_timestamp(first_data_timestamp);

  cout << "last_data_timestamp: ";
  display_timestamp(last_data_timestamp);

  cout << "first_fastclose_timestamp: ";
  display_timestamp(first_fastclose_timestamp);

  cout << "last_fastclose_timestamp: ";
  display_timestamp(last_fastclose_timestamp);

  cout << "first_datafin_timestamp: ";
  display_timestamp(first_datafin_timestamp);

  cout << "last_datafin_timestamp: ";
  display_timestamp(last_datafin_timestamp);

  cout << "first_fin_rst_timestamp: ";
  display_timestamp(first_fin_rst_timestamp);
  
  cout << "packet_count: " << packet_count << " ";
  cout << "data_packet_count: " << data_packet_count << " ";
  cout << "payload_byte_count: " << payload_byte_count << endl;
}
