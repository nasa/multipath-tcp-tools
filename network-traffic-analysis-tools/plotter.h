// 
// plotter.h
//
// Class to generate our xplot files. Tracks some MPTCP-related pieces
// of information like sequence numbers and acknowledgements. Keeps track
// of which colors or tokens to use for a subflow.
// 
#ifndef __MPTCPPARSER_PLOTTER_H
#define __MPTCPPARSER_PLOTTER_H

#include <iostream>
#include <fstream>
#include <stdint.h>
#include <map>
#include <string>

#include "dss.h"
#include "four_tuple.h"
#include "mptcp_connection.h"

#define WHITE_INDEX 7       // index of "white" in valid_colors array
#define VALID_COLOR_SIZE 8  // size of valid_colors array
#define VALID_TOKEN_SIZE 100

#define LOWER_OFFSET 0  // Can be adjusted to reposition tick marks in plots

// these are the valid colors in xplot.org
const std::string valid_colors[VALID_COLOR_SIZE] = {"red", "blue", "yellow", "magenta", "orange", "purple", "pink", "white"};

// overkill. can probably change to make tokens dynamic in the future.
const std::string valid_tokens[VALID_TOKEN_SIZE] = { "TOKEN001", "TOKEN002", "TOKEN003", "TOKEN004", "TOKEN005", "TOKEN006", "TOKEN007", "TOKEN008", "TOKEN009", "TOKEN010", "TOKEN011", "TOKEN012", "TOKEN013", "TOKEN014", "TOKEN015", "TOKEN016", "TOKEN017", "TOKEN018", "TOKEN019", "TOKEN020", "TOKEN021", "TOKEN022", "TOKEN023", "TOKEN024", "TOKEN025", "TOKEN026", "TOKEN027", "TOKEN028", "TOKEN029", "TOKEN030", "TOKEN031", "TOKEN032", "TOKEN033", "TOKEN034", "TOKEN035", "TOKEN036", "TOKEN037", "TOKEN038", "TOKEN039", "TOKEN040", "TOKEN041", "TOKEN042", "TOKEN043", "TOKEN044", "TOKEN045", "TOKEN046", "TOKEN047", "TOKEN048", "TOKEN049", "TOKEN050", "TOKEN051", "TOKEN052", "TOKEN053", "TOKEN054", "TOKEN055", "TOKEN056", "TOKEN057", "TOKEN058", "TOKEN059", "TOKEN060", "TOKEN061", "TOKEN062", "TOKEN063", "TOKEN064", "TOKEN065", "TOKEN066", "TOKEN067", "TOKEN068", "TOKEN069", "TOKEN070", "TOKEN071", "TOKEN072", "TOKEN073", "TOKEN074", "TOKEN075", "TOKEN076", "TOKEN077", "TOKEN078", "TOKEN079", "TOKEN080", "TOKEN081", "TOKEN082", "TOKEN083", "TOKEN084", "TOKEN085", "TOKEN086", "TOKEN087", "TOKEN088", "TOKEN089", "TOKEN090", "TOKEN091", "TOKEN092", "TOKEN093", "TOKEN094", "TOKEN095", "TOKEN096", "TOKEN097", "TOKEN098", "TOKEN099", "TOKEN100"};

class Plotter{
 public:
  // open output files. track whether we color address pairs or 4-tuples.
  // track whether we color with tokens or colors
  Plotter(const char filename[], FourTuple ft, int connection_num, int token_flag, int address_pair_flag, int relative_x_flag, int relative_y_flag);

  // Close output files
  ~Plotter();

  // Parse and plot relevant fields from a DSS option.
  void handle_dss(DSS dss, FourTuple ft, double timestamp, int direction, MPTCPConnection * mptcp_conn);

  // Plots a box for the data level ACK. Updates cumulative ACK line in plot
  void plot_ack(DSS dss, FourTuple ft, double timestamp, int direction, MPTCPConnection * mptcp_conn);
  void plot_ack_line(DSS dss, FourTuple ft, double timestamp, int direction, MPTCPConnection * mptcp_conn);

  // Plot vertical arrow lines for a data segment
  void plot_dsn(DSS dss, FourTuple ft, double timestamp, int direction, MPTCPConnection * mptcp_conn);

  // Mark data fin on plot
  void plot_data_fin(DSS dss, FourTuple ft, double timestamp, int direction, MPTCPConnection * mptcp_conn);

  // check if a four tuple has been assigned a color in this plotter
  bool has_color(FourTuple ft);

  // get stored color of a four tuple. Return 'white' or last token if not found
  std::string get_color(FourTuple ft);

  // add a color mapping for a four tuple if one does not exist yet
  void add_color(FourTuple ft);

  // create a file containing mappings between four tuples and colors/tokens
  void create_mapping();

  void plot_syn(MPTCPConnection * mptcp_conn, double timestamp, int direction, FourTuple ft);

  // Plot a tick mark at the bottom of a plot along with the string passed in
  // as the text argument.
  void plot_tick(int direction, FourTuple ft, MPTCPConnection * mptcp_conn, double timestamp, const char text[]);

  // Plot a tick mark at the bottom of the plots to show where an MPJOIN happens
  void plot_mp_join(MPTCPConnection * mptcp_conn, double timestamp, int direction, FourTuple ft);

  void display_subflows();
  
 private:
  uint64_t origin_max_sequence;  // track max sequence and ack numbers
  uint64_t origin_max_ack;
  uint64_t remote_max_sequence;
  uint64_t remote_max_ack;
  
  double origin_ack_timestamp;   // track timestamp of last ack
  double remote_ack_timestamp;

  std::string output_filename;
  
  std::ofstream origin_plot;
  std::ofstream remote_plot;
  std::map<FourTuple, std::string> colors;

  bool relative_sequence;      // If true, output relative sequence numbers.
                               // Otherwise, output lower 32-bits.
  bool relative_time;          // If true, output relative time offsets
  bool should_tokenize;        // If true, use tokens rather than colors.
  bool address_pair_colors;    // if true, color IP address pairs rather than
                               // four tuples.
};
#endif
