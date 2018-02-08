#include "plotter.h"
#include "parser_utility.h"
#include <iomanip>
#include <stdint.h>

using namespace std;

Plotter::Plotter(const char filename[], FourTuple ft, int connection_num, int token_flag, int address_pair_flag, int relative_x_flag, int relative_y_flag){
  string origin_file = filename;
  string remote_file = filename;
  output_filename = filename;
  output_filename += "-MAPPING.txt";
  should_tokenize = false;
  address_pair_colors = false;
  relative_sequence = false;
  relative_time = false;
  
  if (token_flag){
    should_tokenize = true;
  }
  if (address_pair_flag){
    address_pair_colors = true;
  }
  if (relative_y_flag){
    relative_sequence = true;
  }
  if (relative_x_flag){
    relative_time = true;
  }
  origin_file += "-ORIGIN.xpl";
  remote_file += "-REMOTE.xpl";

  origin_plot.open(origin_file.c_str());
  remote_plot.open(remote_file.c_str());
  
  origin_max_sequence = 0;
  origin_max_ack = 0;

  remote_max_sequence = 0;
  remote_max_ack = 0;

  origin_ack_timestamp = 0;
  remote_ack_timestamp = 0;

  // output headers for xpl files
  if (relative_time) {
    origin_plot << "dtime double\ntitle\nConnection " << connection_num << " ";
    origin_plot << ft.get_src_string() << endl;
    remote_plot << "dtime double\ntitle\nConnection " << connection_num << " ";
    remote_plot << ft.get_dst_string() << endl;
    origin_plot << "xlabel\nrelative time (sec)\n";
    remote_plot << "xlabel\nrelative time (sec)\n";
  } else {
    origin_plot << "timeval double\ntitle\nConnection " << connection_num << " ";
    origin_plot << ft.get_src_string() << endl;
    remote_plot << "timeval double\ntitle\nConnection " << connection_num << " ";
    remote_plot << ft.get_dst_string() << endl;
    origin_plot << "xlabel\ntime (hh:mm:ss)\n";
    remote_plot << "xlabel\ntime (hh:mm:ss)\n";
  }
  if (relative_sequence){
    origin_plot << "ylabel\nMPTCP sequence offset\n";
    remote_plot << "ylabel\nMPTCP sequence offset\n";
  } else {
    origin_plot << "ylabel\nMPTCP sequence number\n";
    remote_plot << "ylabel\nMPTCP sequence number\n";
  }
}

// minor cleanup.
Plotter::~Plotter(){
  origin_plot.close();
  remote_plot.close();
  create_mapping();
}

void Plotter::handle_dss(DSS dss, FourTuple ft, double timestamp, int direction, MPTCPConnection * mptcp_conn){
  if (direction == -1){  // 0, or 1 are valid directions. -1 means something
    return;              // is wrong.
  }
  add_color(ft);  // Does nothing if a color already exists

  // DSS is variable length and may or may not contain certain fields. Check
  // each flag and handle all of the cases.
  if (dss.has_dsn()){
    plot_dsn(dss, ft, timestamp, direction, mptcp_conn);
  }
  if(dss.has_ack()){
    plot_ack(dss, ft, timestamp, direction, mptcp_conn);
  }
  if(dss.is_data_fin()){
    plot_data_fin(dss, ft, timestamp, direction, mptcp_conn);
  }
 }

void Plotter::plot_ack(DSS dss, FourTuple ft, double timestamp, int direction, MPTCPConnection * mptcp_conn){
  // origin sends ack for remote data
  ofstream * output_plot;
  uint64_t output_ack;
  uint64_t topmost_bits;
  uint64_t initial_offset;
  uint64_t initial_toffset = 0;
  
  if (relative_time) {
    initial_toffset = mptcp_conn->get_initial_timestamp();
  }
  
  // figure out the correct plot to write data to based on direction
  if (direction == PKT_SRC_SENT){
    output_plot = &remote_plot;
    topmost_bits = mptcp_conn->get_dst_top_most_sequence_bits();
    initial_offset = mptcp_conn->get_dst_initial_sequence_number64();
  } else if (direction == PKT_DST_SENT){
    output_plot = &origin_plot;
    topmost_bits = mptcp_conn->get_src_top_most_sequence_bits();
    initial_offset = mptcp_conn->get_src_initial_sequence_number64();
  }

  if (dss.has_big_ack()){
    output_ack = dss.get_big_ack();
  } else {
    output_ack = create_64_bit_sequence(topmost_bits, dss.get_ack());    
  }

  if (relative_sequence){
    output_ack = output_ack - initial_offset;
  } else {
    output_ack = (output_ack & 0xFFFFFFFF);
  }
  
  // output a box shape for the ack itself
  (*output_plot) << fixed;
  (*output_plot) << setprecision(6);
  if (dss.is_data_fin()){
    (*output_plot) << "diamond " << (timestamp - initial_toffset) << " ";
  } else {
    (*output_plot) << "box " << (timestamp - initial_toffset) << " ";
  }
  (*output_plot) << output_ack << " " << get_color(ft) << endl;
    
  // Update the ACK line that tracks the maximum ACK seen so far.
  plot_ack_line(dss, ft, timestamp, direction, mptcp_conn);
}

void Plotter::plot_ack_line(DSS dss, FourTuple ft, double timestamp, int direction, MPTCPConnection * mptcp_conn){
  uint64_t ack_num;

  uint64_t * max_ack_base;
  double * ack_timestamp_base;
  ofstream * output_plot;

  uint64_t topmost_bits;
  uint64_t output_ack_lower;
  uint64_t output_ack_higher;

  uint64_t initial_sequence_offset;
  uint64_t initial_toffset = 0;
  
  if (relative_time) {
    initial_toffset = mptcp_conn->get_initial_timestamp();
  }

  // figure out which plot to use. figure out which stored variables to use.
  // Here, 'origin' means connection starter. 'remote' means the passive opener
  if (direction == PKT_DST_SENT){
    output_plot = &origin_plot;
    max_ack_base = &remote_max_ack;
    ack_timestamp_base = &remote_ack_timestamp;
    topmost_bits = mptcp_conn->get_src_top_most_sequence_bits();
    initial_sequence_offset = mptcp_conn->get_src_initial_sequence_number64();
  } else if (direction == PKT_SRC_SENT){
    output_plot = &remote_plot;
    max_ack_base = &origin_max_ack;
    ack_timestamp_base = &origin_ack_timestamp;
    topmost_bits = mptcp_conn->get_dst_top_most_sequence_bits();
    initial_sequence_offset = mptcp_conn->get_dst_initial_sequence_number64();
  } else {
    return;  // something has gone wrong here. bail.
  }

  
  // acks can come in two flavors, 32-bit or 64-bit.
  // We can handle both, and output either a 32-bit number or a 64-bit number
  // that is relative to the initial sequence number.
  if (dss.has_big_ack()){
    ack_num = dss.get_big_ack();
  } else {
    ack_num = create_64_bit_sequence(topmost_bits, dss.get_ack());
  }

  if ((*max_ack_base) == 0){        // true for the first ACK
    (*max_ack_base) = ack_num;
    (*ack_timestamp_base) = timestamp;
    return;
  }

  if (ack_num < (*max_ack_base) && ((ack_num & 0xFFFFFFFF) < 0xFFFF && ((*max_ack_base) - ack_num) > 0xFFFF0000)){
    // ^^ HACKY WRAP AROUND CHECK. CAN DO BETTER.
    if (direction == PKT_SRC_SENT){
      mptcp_conn->increment_dst_topmost();
      ack_num = create_64_bit_sequence(mptcp_conn->get_dst_top_most_sequence_bits(), (ack_num & 0xFFFFFFFF));
    } else if (direction == PKT_DST_SENT){
      mptcp_conn->increment_src_topmost();
      ack_num = create_64_bit_sequence(mptcp_conn->get_src_top_most_sequence_bits(), (ack_num & 0xFFFFFFFF));
    } else {
      return; // for completeness. should never reach this.
    }
  }
    
  if (ack_num >= (*max_ack_base)){
    if (relative_sequence){
      // ack_num needs adjusted based on initial sequence
      output_ack_lower = (*max_ack_base) - initial_sequence_offset;
      output_ack_higher = ack_num - initial_sequence_offset; 
    } else {
      output_ack_lower = ((*max_ack_base) & 0xFFFFFFFF);
      output_ack_higher = (ack_num & 0xFFFFFFFF);
    }
    // always advance ack line to the right
    (*output_plot) << "line " << (*ack_timestamp_base) - initial_toffset << " " << output_ack_lower;
    (*output_plot) << " " << (timestamp - initial_toffset) << " " << output_ack_lower << " green\n";
    // advance ack line vertically when new max ack seen
    if (ack_num > (*max_ack_base)){
      (*output_plot) << "line " << (timestamp - initial_toffset) << " " << output_ack_lower;
      (*output_plot) << " " << (timestamp - initial_toffset) << " " << output_ack_higher << " green\n";
    }
    (*max_ack_base) = ack_num;
    (*ack_timestamp_base) = timestamp;
  }
}

void Plotter::plot_dsn(DSS dss, FourTuple ft, double timestamp, int direction, MPTCPConnection * mptcp_conn){
  ofstream* output_plot;
  uint64_t base_dsn;
  uint64_t topmost_bits;
  uint64_t initial_offset;
  uint64_t initial_toffset = 0;
  
  if (relative_time) {
    initial_toffset = mptcp_conn->get_initial_timestamp();
  }
  
  // figure out which plot to write to
  if (direction == PKT_SRC_SENT){
    output_plot = &origin_plot;
    initial_offset = mptcp_conn->get_src_initial_sequence_number64();
    topmost_bits = mptcp_conn->get_src_top_most_sequence_bits();
  } else if (direction == PKT_DST_SENT){
    output_plot = &remote_plot;
    initial_offset = mptcp_conn->get_dst_initial_sequence_number64();
    topmost_bits = mptcp_conn->get_dst_top_most_sequence_bits();
  } else {
    return; // should not be here
  }

  // xplot.org currently not able to handle 64-bit numbers.
  // FIX: Eventually we will want to always work in 64-bit numbers and will
  //      need to promote 32-bit values to their full 64-bit counterparts
  if(dss.has_big_dsn()){
    base_dsn = dss.get_big_dsn();
  } else {
    base_dsn = create_64_bit_sequence(topmost_bits, dss.get_dsn());
  }

  if (relative_sequence){
    base_dsn = (base_dsn - initial_offset);
  } else {
    base_dsn = (base_dsn & 0xFFFFFFFF);
  }
  
  // draw a vertical line with up and down arrows on each end.
  (*output_plot) << fixed;
  (*output_plot) << setprecision(6);
  (*output_plot) << "line " << (timestamp - initial_toffset) << " ";
  (*output_plot) << base_dsn << " " << (timestamp - initial_toffset) << " ";
  (*output_plot) << (base_dsn + dss.get_payload_length()) << " ";
  (*output_plot) << get_color(ft) << endl;
  (*output_plot) << "darrow " << (timestamp - initial_toffset) << " " << base_dsn;
  (*output_plot) << " " << get_color(ft) << endl;
  (*output_plot) << "uarrow " << (timestamp - initial_toffset) << " ";
  (*output_plot) << (base_dsn + dss.get_payload_length()) << " ";
  (*output_plot) << get_color(ft) << endl;
}

void Plotter::plot_data_fin(DSS dss, FourTuple ft, double timestamp, int direction, MPTCPConnection * mptcp_conn){
  // still have to experiment with the best way to display these
  uint64_t * max_ack_base;
  ofstream * output_plot;
  uint64_t output_ack;
  uint64_t initial_offset;
  uint64_t initial_toffset = 0;
  
  if (relative_time) {
    initial_toffset = mptcp_conn->get_initial_timestamp();
  }
  
  if (direction == PKT_SRC_SENT){
    output_plot = &remote_plot;
    max_ack_base = &origin_max_ack;
    initial_offset = mptcp_conn->get_dst_initial_sequence_number64();
  } else if (direction == PKT_DST_SENT){
    output_plot = &origin_plot;
    max_ack_base = &remote_max_ack;
    initial_offset = mptcp_conn->get_src_initial_sequence_number64();
  } else {
    return;  // should not get here
  }
  
  if (relative_sequence){
    output_ack = (*max_ack_base) - initial_offset;
    // ^^ should convert to relative sequence number eventually
  } else {
    output_ack = (*max_ack_base) & 0xFFFFFFFF;
  }
  
  (*output_plot) << fixed << setprecision(6);
  (*output_plot) << "diamond " << (timestamp - initial_toffset) << " ";
  (*output_plot) << output_ack << " " << get_color(ft) << endl;
  
  (*output_plot) << get_color(ft) << endl;
  (*output_plot) << "atext " << (timestamp - initial_toffset) << " " << output_ack << endl;
  (*output_plot) << "DATA_FIN" << endl;
  
}

bool Plotter::has_color(FourTuple ft){
  map<FourTuple, string>::iterator it1, it2;
  it1 = colors.find(ft);
  ft.reverse();
  it2 = colors.find(ft);
  return (it1 != colors.end() || it2 != colors.end());
}

string Plotter::get_color(FourTuple ft){
  map<FourTuple, string>::iterator it;
  FourTuple color_ft = ft;
  if (address_pair_colors){  // Variable stored during class initialization.
    color_ft.zero_ports();  // Zeroed out ports forces only the IP addresses
                            // of the four tuple to be used.
  }

  // value to return if no color is found
  string return_string = valid_colors[WHITE_INDEX];
  if (should_tokenize){
    return_string = valid_tokens[VALID_TOKEN_SIZE - 1];
  }

  // look for color mapping for either direction of the four tuple
  it = colors.find(color_ft);
  if (it == colors.end()){
    color_ft.reverse();
    it = colors.find(color_ft);
    if (it != colors.end()){
      return_string = it->second;
    }
  } else{
    return_string = it->second;
  }
  return return_string;
}

// store a color for ft if one does not already exist for ft or reverse of ft
void Plotter::add_color(FourTuple ft){
  FourTuple color_ft = ft;
  if(address_pair_colors){
    color_ft.zero_ports();
  }
  if (has_color(color_ft)){
    return;
  }
  int color_index = colors.size();
  if (should_tokenize){  // use tokens
    if (color_index > (VALID_TOKEN_SIZE - 1)){  // off end of token table
      color_index = VALID_TOKEN_SIZE - 1;       // pick last token
    }
    colors.insert(pair<FourTuple, string>(color_ft, valid_tokens[color_index]));
  } else {  // use colors
    if (color_index > WHITE_INDEX){  // off end of color table. pick white
      color_index = WHITE_INDEX;
    }
    colors.insert(pair<FourTuple, string>(color_ft, valid_colors[color_index]));
  }
}

// Creates a two-column file containing four tuples and colors/tokens.
// File uses the same prefix as the source and destination xplot files.
// Example:
//
// 1.2.3.4:1111:2.3.4.5:2345 red
// 1.2.3.4:2222:2.3.4.6:2345 blue
// 1.2.3.4:3333:2.3.4.7:2345 yellow
void Plotter::create_mapping(){
  ofstream mapf;
  mapf.open(output_filename.c_str());
  map<FourTuple, string>::iterator it;
  for(it = colors.begin(); it != colors.end(); it++){
    mapf << it->first.get_src_string() << " " << (it->second) << endl;
  }
  mapf.close();
}

void Plotter::plot_syn(MPTCPConnection * mptcp_conn, double timestamp, int direction, FourTuple ft){
  ofstream * output_plot;
  uint64_t initial_sequence;
  uint64_t initial_toffset = 0;
  
  if (relative_time) {
    initial_toffset = mptcp_conn->get_initial_timestamp();
  }
  
  add_color(ft);

  if (direction == PKT_SRC_SENT){ // timestamp sequence color
    output_plot = &origin_plot;
    initial_sequence = mptcp_conn->get_src_initial_sequence_number64();
  } else if (direction == PKT_DST_SENT){
    output_plot = &remote_plot;
    initial_sequence = mptcp_conn->get_dst_initial_sequence_number64();
  } else {
    return;
  }
  if (relative_sequence){
    initial_sequence = 0;
  } else {
    initial_sequence = (initial_sequence & 0xFFFFFFFF);
  }
  
  (*output_plot) << fixed;
  (*output_plot) << setprecision(6);
  (*output_plot) << "uarrow " << (timestamp - initial_toffset) << " " ;
  (*output_plot) << initial_sequence << " ";
  (*output_plot) << get_color(ft) << endl;
  (*output_plot) << "darrow " << (timestamp - initial_toffset) << " " ;
  (*output_plot) << initial_sequence << " ";
  (*output_plot) << get_color(ft) << endl;
  
  (*output_plot) << get_color(ft) << endl;
  (*output_plot) << "atext " << (timestamp - initial_toffset) << " " ;
  (*output_plot) << initial_sequence << endl;
  (*output_plot) << "SYN " << endl;
}

void Plotter::plot_tick(int direction, FourTuple ft, MPTCPConnection * mptcp_conn, double timestamp, const char text[]){
  ofstream * output_plot;
  uint64_t sequence;
  uint64_t initial_toffset = 0;
  
  if (relative_time) {
    initial_toffset = mptcp_conn->get_initial_timestamp();
  }

  // figure out which plot to use and the correct initial seq num for the plot
  if (direction == PKT_SRC_SENT){
    output_plot = &origin_plot;
    sequence = mptcp_conn->get_src_initial_sequence_number64();
  } else if (direction == PKT_DST_SENT){
    output_plot = &remote_plot;
    sequence = mptcp_conn->get_dst_initial_sequence_number64();
  } else {
    return;
  }

  if (relative_sequence){
    sequence = 0;
  } else {
    sequence = (sequence & 0xFFFFFFFF);
  }
  
  // Plot a tick mark and text near the bottom of the plot.
  // Location along the y-axis can be adjusted before compilation by changing
  // the LOWER_OFFSET constant in plotter.h.
  
  (*output_plot) << fixed;
  (*output_plot) << setprecision(6);

  (*output_plot) << get_color(ft) << endl;
  (*output_plot) << "dtick " << (timestamp - initial_toffset) << " " ;
  (*output_plot) << sequence - LOWER_OFFSET << " ";
  (*output_plot) << get_color(ft) << endl;
  (*output_plot) << "atext " << (timestamp - initial_toffset) << " " ;
  (*output_plot) << sequence - LOWER_OFFSET << endl;
  (*output_plot) << text << endl;  
}

// For now, just use the tick mark method. Perhaps something else in the future.
void Plotter::plot_mp_join(MPTCPConnection * mptcp_conn, double timestamp, int direction, FourTuple ft){
  const char msg[] = "JOIN";
  add_color(ft);
  if (direction == PKT_SRC_SENT || direction == PKT_DST_SENT){
    // timestamp sequence color
    // For now, just slap a tick mark on both plots
    plot_tick(PKT_SRC_SENT, ft, mptcp_conn, timestamp, msg);
    plot_tick(PKT_DST_SENT, ft, mptcp_conn, timestamp, msg);
  }
}

void Plotter::display_subflows(){
  map<FourTuple, string>::iterator it;
  for (it = colors.begin(); it != colors.end(); it++){
    it->first.display();
  }
}
