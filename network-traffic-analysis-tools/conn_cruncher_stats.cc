#include <iostream>
#include "conn_cruncher_stats.h"

using namespace std;


ConnCruncherStats::ConnCruncherStats(){
  data_ptr = NULL;
}

ConnCruncherStats::ConnCruncherStats(struct conn_cruncher_data_struct * data){
  data_ptr = data;
}

void ConnCruncherStats::display(){
  cout << "Connection stats: ";
  cout << data_ptr->subflows[0].get_ft().get_src_string() << " ";
  cout << "num_subflows: " << data_ptr->subflows.size() << " ";
  cout << "origin_key: " << data_ptr->connection->get_src_key() << " ";
  cout << "origin_token: " << data_ptr->connection->get_src_token() << " ";
  cout << "remote_key: " << data_ptr->connection->get_dst_key() << " ";
  cout << "remote_token: " << data_ptr->connection->get_dst_token() << endl;
  
  cout << "Origin Direction: ";
  cout << data_ptr->subflows[0].get_ft().get_src_string() << " ";
  cout << "initial_sequence_number: " << data_ptr->connection->get_src_initial_sequence_number64() << " ";
  cout << "final_sequence_number: " << data_ptr->connection->get_src_last_seq64() << " ";
  cout << data_ptr->orig_dir_subflow.get_short_string() << endl;
  
  cout << "Remote Direction: ";
  cout << data_ptr->reverse_subflows[0].get_ft().get_src_string() << " ";
  cout << "initial_sequence_number: " << data_ptr->connection->get_dst_initial_sequence_number64() << " ";
  cout << "final_sequence_number: " << data_ptr->connection->get_dst_last_seq64() << " ";  
  cout << data_ptr->remote_dir_subflow.get_short_string() << endl;
}
