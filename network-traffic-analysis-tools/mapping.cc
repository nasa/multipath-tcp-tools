#include <cstdlib>
#include <iostream>

#include "mapping.h"

using namespace std;

struct mapping * init_mapping(struct mapping * node, uint32_t sub_seq_num,
			      uint64_t conn_seq_num, uint16_t map_len){
  node = new struct mapping;
  node->subflow_sequence_number = sub_seq_num;
  node->data_level_sequence_number = conn_seq_num;
  node->mapping_len = map_len;
  node->next_mapping = NULL;
  return node;
}

void display_mapping(const struct mapping * m){
  if (m != NULL){
    cout << m->subflow_sequence_number << " ";
    cout << (m->subflow_sequence_number + m->mapping_len) << " ";
    cout << m->data_level_sequence_number << " ";
    cout << (m->data_level_sequence_number + m->mapping_len) << endl;
  }
}

uint64_t lookup_value(const struct mapping * node, uint32_t sub_seq_num){
  uint32_t difference = sub_seq_num - node->subflow_sequence_number;
  uint64_t conn_level_seq = node->data_level_sequence_number + difference;
  return conn_level_seq;
}

Mapper::Mapper(){
  map_list = NULL;
  list_size = 0;
}

Mapper::~Mapper(){
  cleanup_map_list();
  list_size = 0;
}

void Mapper::insert(uint32_t sub_seq_num,
		    uint64_t conn_seq_num, uint16_t map_len){
  if (map_list == NULL){
    map_list = init_mapping(map_list, sub_seq_num, conn_seq_num, map_len);
    map_list->next_mapping = NULL;
    list_size++;
    return;
  }

  if (sub_seq_num < map_list->subflow_sequence_number){
    struct mapping * current = NULL;
    current = init_mapping(current, sub_seq_num, conn_seq_num, map_len);
    current->next_mapping = map_list;
    map_list = current;
    list_size++;
    return;
  }

  struct mapping * current = map_list;
  while (current->next_mapping != NULL &&
	 sub_seq_num > current->next_mapping->subflow_sequence_number){
    current = current->next_mapping;
  }
  struct mapping * next = NULL;
  next = init_mapping(next, sub_seq_num, conn_seq_num, map_len);
  next->next_mapping = current->next_mapping;
  current->next_mapping = next;
  list_size++;
  return;
}

uint64_t Mapper::lookup(const uint32_t& value) const{
  struct mapping * current = map_list;
  while (current != NULL && value >= current->subflow_sequence_number){
    if (value < (current->subflow_sequence_number + current->mapping_len)){
      return lookup_value(current, value);
    }
    current = current->next_mapping;
  }
  return 0;
}

void Mapper::display(){
  if (map_list == NULL)
    return;

  struct mapping * current = map_list;
  while (current != NULL){
    display_mapping(current);
    current = current->next_mapping;
  }
}

void Mapper::cleanup_map_list(){
  if (map_list == NULL)
    return;

  struct mapping * current = map_list;
  struct mapping * next = map_list;

  while (current != NULL){
    next = current->next_mapping;
    current->next_mapping = NULL;
    delete current;
    list_size--;
    current = next;
  }
  map_list = NULL;
}
