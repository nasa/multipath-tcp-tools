//
// layer_handlers.h
//
// A catch-all spot for functions that assist in processing the
// various layers of network packets, especially MPTCP packets.
#ifndef __MPTCPPARSER_LAYER_HANDLERS_H
#define __MPTCPPARSER_LAYER_HANDLERS_H

#include <stdint.h>
#include <pcap.h>
#include <pcap/sll.h>       // struct sll_header 
#include <linux/if_ether.h> // ETH_P_ values

#include "four_tuple.h"
#include "dss.h"

// Values from: tools.ietf.org/html/rfc6824
#define MPTCP_OPT 30
#define MP_CAPABLE 0
#define MP_JOIN 1
#define MP_DSS  2
#define MP_ADD_ADDR 3
#define MP_REM_ADDR 4
#define MP_PRIO 5
#define MP_FAIL 6
#define MP_FASTCLOSE 7

/// my vars

#define MP_PROTOCOL_VER_0 0
#define MP_PROTOCOL_VER_1 1
#define MP_PROTOCOL_NO_VER 99
#define MPTCP_NO_KEY 0


//
//
#define IPV4_VERSION 4
#define IPV6_VERSION 6


//
//  TCP Options can contain kind and length.
//  NOPs only have kind equal to 0x01. length
//  should be ignored in that case.
//
struct tcp_opt{
  uint8_t kind;
  uint8_t length;
};

// POTENTIAL ENDIANNESS PROBLEM. Works for little endian right now.
//
// All MPTCP options will start with these fields.
struct mptcp_opt{
  uint8_t kind;
  uint8_t length;
  uint8_t pad:4;
  uint8_t subtype:4;
};

// POTENTIAL ENDIANNESS PROBLEM. Works for little endian right now.
//
// Parses an MP_CAPABLE option for a TCP SYN for v0 of MPTCP.
struct mp_capable_opt_v0_syn{
  uint8_t kind;
  uint8_t length;
  uint8_t version:4;
  uint8_t subtype:4;
  uint8_t flags;
  uint32_t key_upper;
  uint32_t key_lower;
};

// POTENTIAL ENDIANNESS PROBLEM. Works for little endian right now.
struct mp_capable_opt_ack{
  uint8_t kind;
  uint8_t length;
  uint8_t version:4;
  uint8_t subtype:4;
  uint8_t flags;
  uint32_t sender_key_upper;
  uint32_t sender_key_lower;
  uint32_t receiver_key_upper;
  uint32_t receiver_key_lower;
};

// POTENTIAL ENDIANNESS PROBLEM. Works for little endian right now.
//
// Parses an MP_JOIN option for a TCP SYN for v0 of MPTCP.
struct mp_join_opt_v0_syn{
  uint8_t kind;
  uint8_t length;
  uint8_t backup:1;
  uint8_t padding:3;
  uint8_t subtype:4;
  uint8_t address_id;
  uint32_t token;
  uint32_t rand_num;
};

bool is_ipv4(unsigned int datalink_type, const u_char* packet);
bool is_ipv6(unsigned int datalink_type, const u_char* packet);

bool is_ipv4_tcp(const u_char * packet, const int tcp_offset);

bool is_tcp_syn(const u_char * packet, const int tcp_offset);
bool is_ipv4_tcp_syn(const u_char * packet, const int ip_offset);

bool is_tcp_ack(const u_char * packet, const int tcp_offset);
bool is_ipv4_tcp_ack(const u_char * packet, const int ip_offset);

bool is_tcp_fin(const u_char * packet, const int tcp_offset);
bool is_ipv4_tcp_fin(const u_char * packet, const int ip_offset);

bool is_tcp_rst(const u_char * packet, const int tcp_offset);
bool is_ipv4_tcp_rst(const u_char * packet, const int ip_offset);

FourTuple get_ipv4_tcp_four_tuple(const u_char * packet, const int ip_offset);


bool contains_tcp_option(const u_char* packet, const int tcp_option_offset,
			 const unsigned int len_options, const int target);
bool contains_mptcp_option(const u_char* packet, const int tcp_option_offset,
			   const unsigned int len_options,
			   const unsigned int target);

bool contains_ipv4_mptcp(const u_char* packet, const int ip_offset);
bool contains_ipv4_mptcp_option(const u_char* packet, const int ip_offset,
				const unsigned int target);


uint8_t get_ipv4_mp_capable_version(const u_char* packet, const int ip_offset);
uint64_t get_ipv4_mp_capable_src_key(const u_char* packet, const int ip_offset);
uint64_t get_ipv4_mp_capable_dst_key(const u_char* packet, const int ip_offset);

uint32_t get_ipv4_mp_join_token(const u_char* packet, const int ip_offset);

DSS handle_ipv4_dss(const u_char * packet, const unsigned int ip_offset);

bool contains_ipv4_bare_data(const u_char * packet,
			     const unsigned int ip_offset);

#endif 
