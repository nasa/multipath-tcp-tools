#include "connection_map.h"
#include "layer_handlers.h"
#include <iostream>

using namespace std;

ConnectionMap::ConnectionMap(){
  // map<FourTuple, int> is empty to start
  connection_number = 0;
}

bool ConnectionMap::exists(FourTuple ft){
  map<FourTuple, int>::iterator it;

  it = connections.find(ft);
  if (it == connections.end()){
    // ft not found, look for the reverse
    FourTuple ft_2 = FourTuple(ft);
    ft_2.reverse();
    it = connections.find(ft_2);
    if (it == connections.end()){
      return false;  // neither found
    } else {
      return true;   // reverse ft found
    }
  } else{
    return true;     // ft found
  }
}

unsigned int ConnectionMap::get_direction(FourTuple ft){
  map<FourTuple, int>::iterator it;
  it = connections.find(ft);
  if (it == connections.end()){
    FourTuple ft_2 = FourTuple(ft);
    ft_2.reverse();
    it = connections.find(ft_2);
    if (it == connections.end()){
      return -1; // not found at all
    } else { 
      return 1;  // reverse ft was found. responder is sending
    }
  } else {
    return 0; // original ft was found. origin is sending
  }
}

map<FourTuple, int>::iterator ConnectionMap::find(FourTuple ft){
  map<FourTuple, int>::iterator it;

  it = connections.find(ft);
  if (it == connections.end()){
    FourTuple ft_2 = FourTuple(ft);
    ft_2.reverse();
    it = connections.find(ft_2);
    if (it == connections.end()){
      return connections.end();
    } else {
      return it;  // iterator points to reverse ft
    }
  } else{
    return it;   // iterator points to ft
  }
}

bool ConnectionMap::insert(FourTuple ft){
  pair<map<FourTuple, int>::iterator, bool> ret;
  map<FourTuple, int>::iterator it;
  if (exists(ft)){
    return false;  // return if either ft or reverse ft has been inserted
  }
  ret = connections.insert(pair<FourTuple, int>(ft, connection_number));
  if (ret.second == false){
    return false;       // this should never be the case
  }
  connection_number += 1;    
  return true;
}

int ConnectionMap::erase(FourTuple ft){
  return connections.erase(ft);
}

void ConnectionMap::display(){
  map<FourTuple, int>::iterator it;
  for (it = connections.begin(); it != connections.end(); it++){
    (it->first).display();
    cout << "Subflow number: " << it->second << endl;
  }
}

vector<FourTuple> ConnectionMap::get_four_tuple_ids(){
  vector<FourTuple> ft_vec;
  FourTuple blank_tuple;
  map<FourTuple, int>::iterator it;
  for (it = connections.begin(); it != connections.end(); it++){
    ft_vec.push_back(blank_tuple);
  }
  for (it = connections.begin(); it != connections.end(); it++){
    ft_vec[it->second] = it->first;
  }
  return ft_vec;
}
