#ifndef __MPTCPPARSER_FOUR_TUPLE_H
#define __MPTCPPARSER_FOUR_TUPLE_H


#include <stdint.h>
#include <arpa/inet.h>
#include <string>
#include <sstream>
#include "address.h"

#define FOUR_TUPLE_IPV4 0
#define FOUR_TUPLE_IPV6 1

class FourTuple{
 public:
  FourTuple(){
    src_address = NULL;
    dst_address = NULL;
    src_port = 0;
    dst_port = 0;
  }
  
  FourTuple(int ip_type, uint8_t * src_addr, uint8_t * dst_addr, uint16_t * s_port, uint16_t * d_port){
    if(ip_type == FOUR_TUPLE_IPV4){
      src_address = new IPv4Address();
      dst_address = new IPv4Address();
    }
    else if(ip_type == FOUR_TUPLE_IPV6){
      src_address = new IPv6Address();
      dst_address = new IPv6Address();
    } else {
      src_address = NULL;
      dst_address = NULL;
      return;
    }
    src_address->store_address(src_addr);
    dst_address->store_address(dst_addr);
    src_port = ntohs(*s_port);
    dst_port = ntohs(*d_port);
  }
  ~FourTuple(){
    if (src_address){
      delete src_address;
    }
    if (dst_address){
      delete dst_address;
    }
  }
  FourTuple(const FourTuple &rhs){
    if (rhs.src_address && rhs.dst_address){
      if (rhs.src_address->get_length() == IPV4_LEN_BYTES){
	src_address = new IPv4Address();
	dst_address = new IPv4Address();
      } else if (rhs.src_address->get_length() == IPV6_LEN_BYTES){
	src_address = new IPv6Address();
	dst_address = new IPv6Address();
      }
      src_address->copy_address(rhs.src_address->get_data_address());
      dst_address->copy_address(rhs.dst_address->get_data_address());
      src_port = rhs.src_port;
      dst_port = rhs.dst_port;
    } else {
      src_address = NULL;
      dst_address = NULL;
      src_port = 0;
      dst_port = 0;
    }
  }
  
  
  
  bool operator ==(const FourTuple& rhs) const {
    return (((*src_address) == (*rhs.src_address)) &&
	    ((*dst_address) == (*rhs.dst_address)) &&
	    ((src_port) == (rhs.src_port)) &&
	    ((dst_port) == (rhs.dst_port)));
  }

  bool operator <(const FourTuple& rhs) const {
    if ((*src_address) != (*rhs.src_address)){
      return ((*src_address) < (*rhs.src_address));
    } else if ((*dst_address) != (*rhs.dst_address)){
      return ((*dst_address) < (*rhs.dst_address));
    } else if (src_port != rhs.src_port){
      return (src_port < rhs.src_port);
    }
    return (dst_port < rhs.dst_port);
  }

  bool operator !=(const FourTuple& rhs) const {return !((*this) == rhs);}
  bool operator <=(const FourTuple& rhs) const {return (((*this) == rhs) || ((*this) < rhs));}
  bool operator >(const FourTuple& rhs) const {return !((*this) <= rhs);}
  bool operator >=(const FourTuple& rhs) const {return !((*this) < rhs);}

  FourTuple& operator =(const FourTuple& rhs){
    if (this != &rhs){
      if (rhs.src_address && rhs.dst_address){
	if (src_address && dst_address){
	  delete src_address;
	  delete dst_address;
	}      
	if (rhs.src_address->get_length() == IPV4_LEN_BYTES){
	  src_address = new IPv4Address();
	  dst_address = new IPv4Address();
	} else if (rhs.src_address->get_length() == IPV6_LEN_BYTES){
	  src_address = new IPv6Address();
	  dst_address = new IPv6Address();
	}
	src_address->copy_address(rhs.src_address->get_data_address());
	dst_address->copy_address(rhs.dst_address->get_data_address());	
      }
      src_port = rhs.src_port;
      dst_port = rhs.dst_port;
    }
    return *this;
  }
  
  void display() const;
  void display_err() const;
  void reverse();

  bool has_addresses(){ return (src_address && dst_address); }

  std::string get_src_string() const;
  std::string get_dst_string() const;

  void zero_ports();
  
 private:
  Address* src_address;
  Address* dst_address;
  uint16_t src_port;
  uint16_t dst_port;
};

#endif
