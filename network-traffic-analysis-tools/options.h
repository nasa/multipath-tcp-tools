#ifndef __MPTCPPARSER_OPTIONS_H
#define __MPTCPPARSER_OPTIONS_H

char * handle_options(int argc, char *argv[]);
char * split_handle_options(int argc, char *argv[], int * conn_num);
char * cruncher_handle_options(int argc, char *argv[], int * conn_num);
bool check_if_init();
int get_tflag();
int get_fflag();
int get_flag2();
int get_hflag();
int get_rxflag();
int get_ryflag();
int get_aflag();
int get_jflag();
int get_bflag();
int get_lflag();

int get_split_fflag();
int get_split_nflag();
int get_split_lflag();
int get_split_hflag();
std::string get_split_oname();
int get_split_oflag();

int get_cruncher_fflag();
int get_cruncher_hflag();
int get_cruncher_sflag();
int get_cruncher_cflag();


#endif
