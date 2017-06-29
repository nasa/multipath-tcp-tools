#include <openssl/sha.h>
#include <iostream>
#include <string.h>
#include <arpa/inet.h>
#include "mptcp_connection.h"
#include "parser_utility.h"

using namespace std;

MPTCPConnection::MPTCPConnection(FourTuple st, double timestamp, uint8_t ver){
  source_tuple = st;
  src_key = 0;
  dst_key = 0;
  src_token = 0;
  dst_token = 0;

  version = ver;
  
  initial_timestamp = timestamp;
  last_timestamp = timestamp;

  src_last_seq = 0;
  dst_last_seq = 0;

  sent_dss = false;
}

void MPTCPConnection::display(){
  cout << "Initial subflow: ";
  source_tuple.display();

  cout << hex;
  cout << "Initial sender key: " << src_key << endl;
  cout << "Initial reciever key: " << dst_key << endl;
  cout << "Token from sender key: " << src_token << endl;
  cout << "Token from reciever key: " << dst_token << dec << endl;
  cout << "DSS Option in Stream: " << sent_dss << endl;
}

void MPTCPConnection::display_seq_nums_64(){
  if (!has_dss())
    return;
  
  cout << "Origin initial sequence number: ";
  cout << get_src_initial_sequence_number64() << endl;
  cout << "Origin final sequence number: ";
  cout << get_src_last_seq64() << endl;
  cout << "Remote initial sequence number: ";
  cout << get_dst_initial_sequence_number64() << endl;
  cout << "Remote final sequence number: ";
  cout << get_dst_last_seq64() << endl << endl;

  cout << "Origin Payload Bytes: ";
  cout << (get_src_last_seq64() - get_src_initial_sequence_number64()) << endl;
  cout << "Remote Payload Bytes: ";
  cout << (get_dst_last_seq64() - get_dst_initial_sequence_number64());
  cout << endl << endl;
  cout << "First Packet Timestamp: " <<fixed << get_initial_timestamp() << endl;
  cout << "Last Packet Timestamp: " << fixed << get_last_timestamp() << endl;
  cout << "Duration: "<<fixed<<(get_last_timestamp() - get_initial_timestamp());
  cout << endl;
}

void MPTCPConnection::add_dst_key(uint64_t d_key){
  if (dst_key > 0 && d_key != dst_key){
    cerr << "Warning: Reuse of four tuple ";
    source_tuple.display_err();
    cerr << "Not storing key: " << d_key << endl;
    return;
  }
  dst_key = d_key;

  unsigned char md[SHA_DIGEST_LENGTH];
  unsigned char key_char[sizeof(uint64_t)];
  uint64_t swap_key = htonll(d_key);
  memcpy(key_char, &swap_key, sizeof(uint64_t));
  SHA1(key_char, sizeof(uint64_t), md);

  unsigned char sig_bits[4];
  memcpy(sig_bits, md, sizeof(unsigned char)*4);
  dst_token = ntohl(*(uint32_t*)sig_bits);
  
  unsigned char sequence_bits[8];
  memcpy(sequence_bits, &md[(SHA_DIGEST_LENGTH - 8)], sizeof(unsigned char) * 8);
  dst_initial_sequence_number = ntohll(*(uint64_t*)sequence_bits);
  if (dst_last_seq == 0){
    dst_last_seq = ntohll(*(uint64_t*)sequence_bits);
  }
  dst_top_most_sequence_bits = ntohl(*(uint32_t*)sequence_bits);
  dst_top_most_sequence_bits = (dst_top_most_sequence_bits << 32);
}

void MPTCPConnection::add_src_key(uint64_t s_key){
  if (src_key > 0 && s_key != src_key){
    cerr << "Warning: Reuse of four tuple ";
    source_tuple.display_err();
    cerr << "Not storing key: " << s_key << endl;
    return;
  }
  src_key = s_key;

  unsigned char md[SHA_DIGEST_LENGTH];
  unsigned char key_char[sizeof(uint64_t)];
  uint64_t swap_key = htonll(s_key);
  memcpy(key_char, &swap_key, sizeof(uint64_t));
  SHA1(key_char, sizeof(uint64_t), md);

  unsigned char sig_bits[4];
  memcpy(sig_bits, md, sizeof(unsigned char)*4);
  src_token = ntohl(*(uint32_t*)sig_bits);
  
  unsigned char sequence_bits[8];
  memcpy(sequence_bits, &md[(SHA_DIGEST_LENGTH - 8)], sizeof(unsigned char) * 8);
  src_initial_sequence_number = ntohll(*(uint64_t*)sequence_bits);
  if (src_last_seq == 0){
    src_last_seq = ntohll(*(uint64_t*)sequence_bits);
  }
  src_top_most_sequence_bits = ntohl(*(uint32_t*)sequence_bits);
  src_top_most_sequence_bits = (src_top_most_sequence_bits << 32);
}

bool MPTCPConnection::token_matches(uint32_t tok){
  return (src_token_matches(tok) || dst_token_matches(tok));
}

bool MPTCPConnection::src_token_matches(uint32_t tok){
  return (tok == src_token);
}

bool MPTCPConnection::dst_token_matches(uint32_t tok){
  return (tok == dst_token);
}

void MPTCPConnection::store_dss(DSS dss, int direction){
  uint64_t sequence = 0;
  if (dss.has_big_dsn()){
    sequence = dss.get_big_dsn();
    sent_dss = true;
  } else if (dss.has_dsn()){
    sequence = (dss.get_dsn() & 0x00000000FFFFFFFF);
    sent_dss = true;
  }

  if (direction == PKT_SRC_SENT){
    if ((get_src_top_most_sequence_bits() | sequence) > sequence){
      sequence = get_src_top_most_sequence_bits() | sequence;
    }
    store_src_seq(sequence + dss.get_payload_length());
  } else if (direction == PKT_DST_SENT){
    if ((get_dst_top_most_sequence_bits() | sequence) > sequence){
      sequence = get_dst_top_most_sequence_bits() | sequence;
    }
    store_dst_seq(sequence + dss.get_payload_length());
  } else {
    return;
  }
}

bool MPTCPConnection::has_dss(){
  return sent_dss;
}

void MPTCPConnection::store_src_seq(uint64_t new_seq){
  if (new_seq > src_last_seq){
    src_last_seq = new_seq;
  }
}

void MPTCPConnection::store_dst_seq(uint64_t new_seq){
  if (new_seq > dst_last_seq){
    dst_last_seq = new_seq;
  }
}
