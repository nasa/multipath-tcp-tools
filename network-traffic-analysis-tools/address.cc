#include "address.h"

#include <stdint.h>
#include <cstddef>
#include <iostream>
#include <cstring>
#include <arpa/inet.h>
#include <cstdlib>

#include "parser_utility.h"


#define IPV4_LEN_BYTES 4
#define IPV6_LEN_BYTES 8

void Address::display(){
  std::cout << "My length is: " << (int)length << " bytes and ";
  if (addr){
    std::cout << "I contain: ";
    for (int i = 0; i < length; i++){
      std::cout << std::hex << (int)addr[i];
      if (i < length - 1){
	std::cout << ".";
      }
    }
    std::cout << std::dec;
    if (length == IPV4_LEN_BYTES){
      std::cout << " (" << (*(uint32_t*)addr) << ")";
    } else if (length == IPV6_LEN_BYTES){
	std::cout << " (" << (*(uint64_t*)addr) << ")";
    }
  } else {
    std::cout << "I am empty.";
  }
  std::cout << std::endl;
}

void Address::display_err(){
  std::cerr << "My length is: " << (int)length << " bytes and ";
  if (addr){
    std::cerr << "I contain: ";
    for (int i = 0; i < length; i++){
      std::cerr << std::hex << (int)addr[i];
      if (i < length - 1){
	std::cerr << ".";
      }
    }
    std::cerr << std::dec;
    if (length == IPV4_LEN_BYTES){
      std::cerr << " (" << (*(uint32_t*)addr) << ")";
    } else if (length == IPV6_LEN_BYTES){
	std::cerr << " (" << (*(uint64_t*)addr) << ")";
    }
  } else {
    std::cerr << "I am empty.";
  }
  std::cerr << std::endl;
}


void IPv4Address::store_address(uint8_t *data){
  if (!addr){
    addr = new uint8_t[length];
  }
  memcpy(addr, data, length);
  uint32_t host_bytes = ntohl(*(uint32_t*)addr);
  memcpy(addr, &host_bytes, length);
}

void IPv4Address::copy_address(uint8_t * data){
  if (!addr){
    addr = new uint8_t[length];
  }
  memcpy(addr, data, length);
}

std::string IPv4Address::formatted_string(){
  if (!addr){
    return "NO_IPV4_ALLOCATED";
  }
  std::stringstream ss;
  uint32_t network_bytes = htonl(*(uint32_t*)addr);
  unsigned char * it = (unsigned char*)&network_bytes;
  int tmp = 0;
  for (int i = 0; i < length; i++){
    tmp = *(it + i);
    ss << tmp;
    if (i < length - 1){
      ss << ".";
    }
  }
  return ss.str();
}

void IPv6Address::store_address(uint8_t *data){
  if (!addr){
    addr = new uint8_t[length];
  }
  memcpy(addr, data, length);
  (*addr) = ntohll(*(uint64_t*)addr);
}

void IPv6Address::copy_address(uint8_t * data){
  if (!addr){
    addr = new uint8_t[length];
  }
  memcpy(addr, data, length);
}

std::string IPv6Address::formatted_string(){
  if (!addr){
    return "NO_IPV4_ALLOCATED";
  }
  std::stringstream ss;
  uint64_t network_bytes = htonll(*(uint64_t*)addr);
  unsigned char * it = (unsigned char*)&network_bytes;
  int tmp = 0;
  for (int i = 0; i < length; i++){
    tmp = *(it + i);
    ss << tmp;
    if (i < length - 1){
      ss << ".";
    }
  }
  return ss.str();  
}
