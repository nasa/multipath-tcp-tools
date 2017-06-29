#include "four_tuple.h"

void FourTuple::display() const {
  std::cout << get_src_string() << std::endl;
}

void FourTuple::display_err() const {
  std::cerr << get_src_string() << std::endl;
}

void FourTuple::reverse(){
  Address* tmp_addr;
  uint16_t tmp_port;
  tmp_addr = src_address;
  src_address = dst_address;
  dst_address = tmp_addr;

  tmp_port = src_port;
  src_port = dst_port;
  dst_port = tmp_port;
}

std::string FourTuple::get_src_string() const {
  std::stringstream ss;
  ss << src_address->formatted_string() << ":";
  ss << src_port << ":";
  ss << dst_address->formatted_string() << ":";
  ss << dst_port;
  return ss.str();
}

std::string FourTuple::get_dst_string() const {
  std::stringstream ss;
  ss << dst_address->formatted_string() << ":";
  ss << dst_port << ":";
  ss << src_address->formatted_string() << ":";
  ss << src_port;
  return ss.str();
}

void FourTuple::zero_ports(){
  src_port = 0;
  dst_port = 0;
}
