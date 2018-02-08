#include <unistd.h>
#include <stdlib.h>
#include <iostream>
#include <cstdio>

#include "options.h"

using namespace std;

#define TFLAG_INIT 0
#define FFLAG_INIT 0
#define FLAG2_INIT 0
#define HFLAG_INIT 0
#define RFLAG_INIT 0
#define AFLAG_INIT 0
#define JFLAG_INIT 0
#define BFLAG_INIT 0
#define LFLAG_INIT 0

#define SPLIT_FFLAG_INIT 0
#define SPLIT_NFLAG_INIT 0
#define SPLIT_LFLAG_INIT 0
#define SPLIT_HFLAG_INIT 0
#define SPLIT_ONAME_INIT "outfile.pcap"
#define SPLIT_OFLAG_INIT 0

#define CRUNCHER_FFLAG_INIT 0
#define CRUNCHER_HFLAG_INIT 0
#define CRUNCHER_SFLAG_INIT 0
#define CRUNCHER_CFLAG_INIT 0

static int g_tflag(TFLAG_INIT);
static int g_fflag(FFLAG_INIT);
static int g_flag2(FLAG2_INIT);
static int g_hflag(HFLAG_INIT);
static int g_rxflag(RFLAG_INIT);
static int g_ryflag(RFLAG_INIT);
static int g_aflag(AFLAG_INIT);
static int g_jflag(JFLAG_INIT);
static bool g_initialized(false);
static int g_bflag(BFLAG_INIT);
static int g_lflag(LFLAG_INIT);

static int g_split_fflag(SPLIT_FFLAG_INIT);
static int g_split_nflag(SPLIT_NFLAG_INIT);
static int g_split_lflag(SPLIT_LFLAG_INIT);
static int g_split_hflag(SPLIT_HFLAG_INIT);
static string g_split_oname(SPLIT_ONAME_INIT);
static int g_split_oflag(SPLIT_OFLAG_INIT);

static int g_cruncher_fflag(CRUNCHER_FFLAG_INIT);
static int g_cruncher_hflag(CRUNCHER_HFLAG_INIT);
static int g_cruncher_sflag(CRUNCHER_SFLAG_INIT);
static int g_cruncher_cflag(CRUNCHER_CFLAG_INIT);

char * handle_options(int argc, char *argv[]){
  int c, err = 0;
  char *pcap_fname = NULL;

  
  static char usage[] = "\nusage: %s [-2abjltr] pcap_filename\n";
  static char help_text[] = "pcap_filename:  pcap file containing MPTCP traffic to process.\n\n"
    "-2:  Generate colors based on address pairs rather than four-tuples.\n\n"
    "-a:  Turn on basic ADD_ADDR and REM_ADDR ticks.\n\n"
    "-b:  Output basic connection information.\n\n"
    "-j:  Turn on JOIN ticks.\n\n"
    "-l:  Output long connection information.\n\n"
    "-r:  [Deprecated: Use -y] Output relative sequence numbers.\n\n"
    "-x:  Output relative time.\n\n"
    "-y:  Output relative sequence numbers.\n\n"
    "-t:  Output TOKEN values rather than colors.\n\n";    

  while ((c = getopt(argc, argv, "t2hrajblxy")) != -1){
    switch(c){
    case 't':
      g_tflag = 1;
      break;
    case '2':
      g_flag2 = 1;
      break;
    case 'r':
    case 'y':
      g_ryflag = 1;
      break;
    case 'x':
      g_rxflag = 1;
      break;
    case 'h':
      g_hflag = 1;
      err = 1;
      break;
    case 'a':
      g_aflag = 1;
      break;
    case 'j':
      g_jflag = 1;
      break;
    case 'b':
      g_bflag = 1;
      break;
    case 'l':
      g_lflag = 1;
      break;
    case '?':
      err = 1;
      break;
    }
  }
  unsigned int filename_count = 0;
  for (int i = optind; i < argc; ++i){
    g_fflag = 1;
    pcap_fname = argv[i];
    ++filename_count;
  }

  g_initialized = true; // store that we can read values
  
  /*
   *  Check for file to open.
   *  Should probably remove the need for the -f flag and just treat the
   *  last argument as the file to open.
   */
  if (filename_count != 1){
    if (filename_count > 1){
      cerr << "Error: Too many filenames passed on the command line.\n";
    }
    err = 1;
  }  

  
  if (err == 1){
    fprintf(stderr, usage, argv[0]);
    if (get_hflag() == 1){
      cerr << help_text;
    }
    return NULL;
  }
  
  return pcap_fname;
}

char * split_handle_options(int argc, char *argv[], int * conn_num){
  int c, err = 0;
  char *pcap_fname = NULL;

  
  static char usage[] = "\nusage: %s [-lh] [-n connection_num] [-o outfile_name] pcap_filename\n";
  static char help_text[] = "pcap_filename:  pcap file containing MPTCP traffic to process.\n\n"
    "-h:  List this help text and exit.\n\n"
    "-l:  List out MP_CAPABLE four_tuples and connection numbers.\n\n"
    "-n:  Connection number to output.\n\n"
    "-o outfile_name:  Name of output file to write packets.\n\n";
  
  
  while ((c = getopt(argc, argv, "n:hlo:")) != -1){
    switch(c){
    case 'o':
      g_split_oflag = 1;
      g_split_oname = optarg;
      break;
    case 'n':
      g_split_nflag = 1;
      (*conn_num) = atoi(optarg);
      break;
    case 'l':
      g_split_lflag = 1;
      break;
    case 'h':
      g_split_hflag = 1;
      err = 1;
      break;
    case '?':
      err = 1;
      break;
    }
  }
  unsigned int filename_count = 0;
  for (int i = optind; i < argc; ++i){
    g_split_fflag = 1;
    pcap_fname = argv[i];
    ++filename_count;
  }
  
  g_initialized = true; // store that we can read values
  
  /*
   *  Check for file to open.
   *  Should probably remove the need for the -f flag and just treat the
   *  last argument as the file to open.
   */
  if (filename_count != 1){
    if (filename_count > 1){
      cerr << "Error: Too many filenames passed on the command line.\n";
    }
    err = 1;
  }
  
  if (err == 1){
    fprintf(stderr, usage, argv[0]);
    if (get_split_hflag() == 1){
      cerr << help_text;
    }
    return NULL;
  }
  
  return pcap_fname;
}

char * cruncher_handle_options(int argc, char *argv[], int * conn_num){
  int c, err = 0;
  char *pcap_fname = NULL;

  
  static char usage[] = "\nusage: %s [-chs] pcap_filename\n";
  static char help_text[] = "pcap_filename:  pcap file containing MPTCP traffic to process.\n\n"
    "-c:  Display connection-level information.\n\n"
    "-h:  List this help text and exit.\n\n"
    "-s:  Display subflow-level information.\n\n";
  
  while ((c = getopt(argc, argv, "hsc")) != -1){
    switch(c){
    case 'h':
      g_cruncher_hflag = 1;
      err = 1;
      break;
    case 's':
      g_cruncher_sflag = 1;
      break;
    case 'c':
      g_cruncher_cflag = 1;
      break;
    case '?':
      err = 1;
      break;
    }
  }
  unsigned int filename_count = 0;
  for (int i = optind; i < argc; ++i){
    g_cruncher_fflag = 1;
    pcap_fname = argv[i];
    ++filename_count;
  }


  g_initialized = true; // store that we can read values
  
  /*
   *  Check for file to open.
   *  Should probably remove the need for the -f flag and just treat the
   *  last argument as the file to open.
   */
  if (filename_count != 1){
    if (filename_count > 1){
      cerr << "Error: Too many filenames passed on the command line.\n";
    }
    err = 1;
  }
  
  if (err == 1){
    fprintf(stderr, usage, argv[0]);
    if (get_cruncher_hflag() == 1){
      cerr << help_text;
    }
    return NULL;
  }
  
  return pcap_fname;
}

bool check_if_init(){
  if (g_initialized){
    return true;
  }
  cerr << "Warning: calling a global variable before it is initialized.\n";
  cerr << "Returning default value." << endl;
  return false;
}

int get_tflag(){
  if (check_if_init()){
    return g_tflag;
  }
  return TFLAG_INIT;
}

int get_fflag(){
  if (check_if_init()){
    return g_fflag;
  }
  return FFLAG_INIT;
}

int get_flag2(){
  if (check_if_init()){
    return g_flag2;
  }
  return FLAG2_INIT;
}

int get_hflag(){
  if (check_if_init()){
    return g_hflag;
  }
  return HFLAG_INIT;
}

int get_rxflag(){
  if (check_if_init()){
    return g_rxflag;
  }
  return RFLAG_INIT;
}

int get_ryflag(){
  if (check_if_init()){
    return g_ryflag;
  }
  return RFLAG_INIT;
}

int get_aflag(){
  if (check_if_init()){
    return g_aflag;
  }
  return AFLAG_INIT;
}

int get_jflag(){
  if (check_if_init()){
    return g_jflag;
  }
  return JFLAG_INIT;
}

int get_bflag(){
  if (check_if_init()){
    return g_bflag;
  }
  return BFLAG_INIT;
}

int get_lflag(){
  if (check_if_init()){
    return g_lflag;
  }
  return LFLAG_INIT;
}


int get_split_fflag(){
  if (check_if_init()){
    return g_split_fflag;
  }
  return SPLIT_FFLAG_INIT;
}

int get_split_nflag(){
  if (check_if_init()){
    return g_split_nflag;
  }
  return SPLIT_NFLAG_INIT;
}

int get_split_lflag(){
  if (check_if_init()){
    return g_split_lflag;
  }
  return SPLIT_LFLAG_INIT;
}

int get_split_hflag(){
  if (check_if_init()){
    return g_split_hflag;
  }
  return SPLIT_HFLAG_INIT;
}

string get_split_oname(){
  if (check_if_init()){
    return g_split_oname;
  }
  return SPLIT_ONAME_INIT;
}

int get_split_oflag(){
  if (check_if_init()){
    return g_split_oflag;
  }
  return SPLIT_OFLAG_INIT;
}

int get_cruncher_hflag(){
  if (check_if_init()){
    return g_cruncher_hflag;
  }
  return CRUNCHER_HFLAG_INIT;
}

int get_cruncher_fflag(){
  if (check_if_init()){
    return g_cruncher_fflag;
  }
  return CRUNCHER_FFLAG_INIT;
}

int get_cruncher_sflag(){
  if (check_if_init()){
    return g_cruncher_sflag;
  }
  return CRUNCHER_SFLAG_INIT;
}

int get_cruncher_cflag(){
  if (check_if_init()){
    return g_cruncher_cflag;
  }
  return CRUNCHER_CFLAG_INIT;
}
