#ifndef __MPTCPPARSER_MAPPING_H
#define __MPTCPPARSER_MAPPING_H

#include <stdint.h>

struct mapping{
  uint32_t subflow_sequence_number;
  uint64_t data_level_sequence_number;
  uint16_t mapping_len;
  struct mapping * next_mapping;
};

struct mapping * init_mapping(struct mapping * node, uint32_t sub_seq_num,
			      uint64_t conn_seq_num, uint16_t map_len);

void display_mapping(const struct mapping * m);

uint64_t lookup_value(const struct mapping * node, uint32_t sub_seq_num);

class Mapper{
 public:
  Mapper();
  ~Mapper();

  void insert(uint32_t sub_seq_num, uint64_t conn_seq_num, uint16_t map_len);

  uint64_t lookup(const uint32_t& value) const;
  
  void display();

  unsigned int size(){return list_size;}
  
 private:
  void cleanup_map_list();
  
  struct mapping * map_list;
  unsigned int list_size;
};

#endif
