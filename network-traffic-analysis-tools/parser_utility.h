#ifndef __MPTCPPARSER_PARSER_UTILITY_H
#define __MPTCPPARSER_PARSER_UTILITY_H

#include <string>
#include <stdint.h>
#include <sstream>

#define PKT_UNKNOWN_DIR -1
#define PKT_SRC_SENT 0
#define PKT_DST_SENT 1


//
// htonll - 64-bit value host to net function.
// Changes endianness for 64-bit values when necessary.
uint64_t htonll(uint64_t value);

//
// ntohll - 64-bit value net to host function.
// Changes endianness for 64-bit values when necessary. 
uint64_t ntohll(uint64_t value);

//
// print_hex_memory - Print out memory as hex values.
void print_hex_memory(const void *mem, const int length);

//
// Return a 64-bit number by replacing the least significant bits of
// 'most_significant_bits' with 'least_significant_bits'.
uint64_t create_64_bit_sequence(uint64_t most_significant_bits, uint32_t least_significant_bits);


namespace patch{
  template < typename T > std::string to_string( const T& n){
    std::ostringstream stm;
    stm << n;
    return stm.str();
  }
}

#endif
