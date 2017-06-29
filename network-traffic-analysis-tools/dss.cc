#include "dss.h"
#include "parser_utility.h"
#include <string.h>
#include <arpa/inet.h>
#include <iostream>

using namespace std;

DSS::DSS(){
  option_header.kind = 0;
  option_header.length = 0;
  option_header.pad1 = 0;
  option_header.subtype = 0;
  option_header.ack = 0;
  option_header.big_ack = 0;
  option_header.dsn = 0;
  option_header.big_dsn = 0;
  option_header.data_fin = 0;
  option_header.pad2 = 0;

  data_ack = 0;
  data_sequence_num = 0;
  big_data_ack = 0;
  big_data_sequence_num = 0;
  subflow_sequence_num = 0;
  data_level_length = 0;
  checksum = 0;

  payload_length = 0;
  
  initialized_with_args = false;
}

DSS::DSS(const unsigned char * option_start, uint16_t payload_len){
  unsigned int ack_length = 0;
  unsigned int seq_length = 0;

  payload_length = 0;
  data_level_length = 0;
  checksum = 0;
  
  // Assume option_start points to a valid chunk of memory at the start
  // of a DSS option. Store that option header.
  memcpy(&option_header, option_start, sizeof(struct base_dss_option));

  // DSS is variable size depending on if an ACK or sequence number is present.
  // Furter, ACKs and sequence numbers may be either 32 or 64 bits long.
  // Check for presence and length of each so pointer arithmetic works.
  
  if (option_header.ack == 1){  // ACK present
    if (option_header.big_ack != 1){  // ACK is 32-bits
      data_ack = ntohl(*(uint32_t *)(option_start + sizeof(struct base_dss_option)));
      ack_length = sizeof(uint32_t);
    } else {  // ACK is 64-bits
      big_data_ack = ntohll(*(uint64_t *)(option_start + sizeof(struct base_dss_option)));
      ack_length = sizeof(uint64_t);
    }
  }

  if (option_header.dsn == 1){  // Data Sequence Number present
    payload_length = payload_len;
    if (option_header.big_dsn != 1){  // DSN is 32 bits
      data_sequence_num = ntohl(*(uint32_t *)(option_start + sizeof(struct base_dss_option) + ack_length));
      seq_length = sizeof(uint32_t);
    } else {  // DSN is 64 bits
      big_data_sequence_num = ntohll(*(uint64_t *)(option_start + sizeof(struct base_dss_option) + ack_length));
      seq_length = sizeof(uint64_t);
    }

    // offset past initial header, ack, and data sequence number
    subflow_sequence_num = ntohl(*(uint32_t *)(option_start + sizeof(struct base_dss_option) + ack_length + seq_length));

    // offset past initial header, ack, data sequence number, and subflow
    // sequence number
    data_level_length = ntohs(*(uint16_t *)(option_start + sizeof(struct base_dss_option) + ack_length + seq_length + sizeof(uint32_t)));

    // offset past initial header, ack, data sequence number, subflow sequence
    // number, and data level length
    checksum = ntohs(*(uint16_t *)(option_start + sizeof(struct base_dss_option) + ack_length + seq_length + sizeof(uint32_t) + sizeof(uint16_t)));
  }
  
  initialized_with_args = true;
}

void DSS::display(){
  if (!was_initialized_with_args()){
    return;
  }
  cout << "Kind: " << (unsigned int)option_header.kind;
  cout << " Length: " << (unsigned int)option_header.length;
  cout << " Subtype: " << (unsigned int)option_header.subtype;
  cout << " Ack: " << (unsigned int)option_header.ack;
  cout << " BigAck: " << (unsigned int)option_header.big_ack;
  cout << " Dsn: " << (unsigned int)option_header.dsn;
  cout << " BigDsn: " << (unsigned int)option_header.big_dsn;
  cout << " Fin: " << (unsigned int)option_header.data_fin;

  if (option_header.ack == 1){
    if (option_header.big_ack == 1){
      cout << " DataAck: " << big_data_ack;
    } else {
      cout << " DataAck: " << data_ack;
    }
  }

  if (option_header.dsn == 1){
    if(option_header.big_dsn == 1){
      cout << " DSN: " << big_data_sequence_num;
    } else {
      cout << " DSN: " << data_sequence_num;
    }
    cout << " SSN: " << subflow_sequence_num;
    cout << " DLL: " << (unsigned int) data_level_length;
    cout << " Checksum: " << (unsigned int) checksum;
  }
  cout << endl;
}
