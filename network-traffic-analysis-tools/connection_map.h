// 
// connection_map.h
//
// Store and operate on mappings between FourTuple and connection numbers.
// This class considers both directions a FourTuple can represent when
// mapping a FourTuple to a connection number.
//
// Example:
// 10.155.0.1:1234:10.155.0.2:2345 and 10.155.0.2:2345:10.155.0.1:1234
// would both map to the same connection number.
#ifndef __MPTCPPARSER_CONNECTION_MAP_H
#define __MPTCPPARSER_CONNECTION_MAP_H

#include <map>
#include <vector>
#include "four_tuple.h"

class ConnectionMap{
 public:
  // Initializes connection_number to zero.
  ConnectionMap();

  // Stores ft if neither ft or the reverse of ft has been stored before.
  // I assume that the first time ft is passed to insert is from the initial
  // SYN of a given subflow.
  bool insert(FourTuple ft);

  int erase(FourTuple ft);
  
  int size(){return connection_number;}
  
  // Returns an interator to ft or the reverse of ft if either is found.
  std::map<FourTuple, int>::iterator find(const FourTuple ft);

  // Return true if ft or reverse of ft is found in connections.
  bool exists(const FourTuple ft);

  // Return 0 if ft is found in connections.
  // Return 1 if reverse of ft is found in connections.
  // Return -1 if neither ft nor reverse of ft is found in connections.
  // Since the initial SYN
  unsigned int get_direction(const FourTuple ft);

  std::map<FourTuple, int>::iterator end(){return connections.end();}

  void display();

  std::vector<FourTuple> get_four_tuple_ids();
  
 private:
  std::map<FourTuple, int> connections;
  int connection_number;
};


#endif
