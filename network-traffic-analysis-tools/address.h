#ifndef __MPTCPPARSER_ADDRESS_H
#define __MPTCPPARSER_ADDRESS_H


#include <stdint.h>
#include <cstddef>
#include <iostream>
#include <cstring>
#include <string>
#include <sstream>

#define IPV4_LEN_BYTES 4
#define IPV6_LEN_BYTES 8

/*
 *  Right now, just store addresses in network byte order directly from
 *  packet traces. This makes the comparison operators somewhat clunky, but
 *  as long as we are consistent, then it should be fine. Perhaps we should 
 *  perform a nthol or 64-bit equivalent in the future.
 *
 *  We really just need consistent operations for storing four tuples in 
 *  a Map of sorts.
 *
 */

class Address{
 public:
  virtual ~Address(){
    if (addr){
      delete addr;
      addr = NULL;
    }
  }
  virtual void store_address(uint8_t *data) = 0;
  virtual void copy_address(uint8_t *data) = 0;
  
  void display();
  void display_err();
  
  bool operator <(const Address& a) const {
    if (length < a.length){
      return true;
    }
    if (length == IPV4_LEN_BYTES){
      return ((*(uint32_t*)addr) < (*(uint32_t*)a.addr));
    }
    if (length == IPV6_LEN_BYTES){
      return ((*(uint64_t*)addr) < (*(uint64_t*)a.addr));
    }
    
    // should not ever return this 
    return false;
  }

  bool operator ==(const Address& a) const {
    if (length != a.length){
      return false;
    }
    if (length == IPV4_LEN_BYTES){
      return ((*(uint32_t*)addr) == (*(uint32_t*)a.addr));
    }
    if (length == IPV6_LEN_BYTES){
      return ((*(uint64_t*)addr) == (*(uint64_t*)a.addr));
    }
    return false;
  }

  bool operator !=(const Address& a) const { return !(*this == a);}
  bool operator >=(const Address& a) const { return !(*this < a);}
  bool operator <=(const Address& a) const { return ((*this < a)||(*this == a));}
  bool operator >(const Address& a) const { return (!(*this < a) && !(*this == a));}

  uint8_t get_length() const { return length; }
  uint8_t* get_addr() const { return addr; }
  uint8_t * get_data_address(){ return addr; }

  virtual std::string formatted_string() = 0;
  
 protected:
  uint8_t *addr;
  uint8_t length;
};

class IPv4Address : public Address{
 public:
  IPv4Address(){
    length = IPV4_LEN_BYTES;
    addr = NULL;
  }
  ~IPv4Address(){
    if (addr){
      delete[] addr;
      addr = NULL;
    }
  }

  void store_address(uint8_t *data);
  void copy_address(uint8_t * data);
  std::string formatted_string();
};

class IPv6Address : public Address{
 public:
  IPv6Address(){
    length = IPV6_LEN_BYTES;
    addr = NULL;
  }
  ~IPv6Address(){
    if (addr){
      delete[] addr;
      addr = NULL;
    }
  }

  void store_address(uint8_t *data);
  void copy_address(uint8_t * data);
  std::string formatted_string();
};

#endif
