#include <iostream>
#include <arpa/inet.h>      // ntohs
#include <stdio.h>

#include "parser_utility.h"

using namespace std;


uint64_t htonll(uint64_t value){
  static const int num = 42;
  if (*reinterpret_cast<const char*>(&num) == num){
    const uint32_t high_part = htonl(static_cast<uint32_t>(value >> 32));
    const uint32_t low_part = htonl(static_cast<uint32_t>(value & 0xFFFFFFFF));
    return (static_cast<uint64_t>(low_part) << 32) | high_part;
  } else {
    return value;
  }
}

uint64_t ntohll(uint64_t value){
  return htonll(value);
}

void print_hex_memory(const void *mem, const int length){
  unsigned char *p = (unsigned char *)mem;
  for(int i = 0; i < length; i++){
    printf("%02x ",p[i]);
    if (i > 0){
      if ((i + 1) % 16 == 0){
	printf("\n");
      } else if ((i + 1) % 8 == 0){
	printf(" ");
      }
    }
  }
  printf("\n\n");
}

// Replace the least significant 32-bits of most_significant_bits with
// least_significant_bits and return the new number.
uint64_t create_64_bit_sequence(uint64_t most_significant_bits, uint32_t least_significant_bits){
  uint64_t tmp = (uint64_t)least_significant_bits & 0x00000000ffffffff;
  uint64_t tmp2 = most_significant_bits & 0xffffffff00000000;
  tmp = tmp | tmp2;
  return tmp;
}
