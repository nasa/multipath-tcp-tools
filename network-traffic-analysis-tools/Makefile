PREFIX ?=/usr/local

CXX = g++
CXXFLAGS = -g -Wall -Wpedantic
CPPFLAGS = 
LDLIBS = -lpcap -lcrypto -lssl

mptcpplot_objects = mptcpparser.o layer_handlers.o address.o four_tuple.o connection_map.o parser_utility.o mptcp_connection.o plotter.o dss.o processing.o options.o mapping.o

mptcpsplit_objects = mptcpsplit.o layer_handlers.o address.o four_tuple.o connection_map.o parser_utility.o mptcp_connection.o plotter.o dss.o processing.o options.o mapping.o split_processing.o

mptcpcrunch_objects = conn_cruncher.o layer_handlers.o address.o four_tuple.o connection_map.o parser_utility.o mptcp_connection.o plotter.o dss.o processing.o options.o mapping.o split_processing.o subflow.o conn_crunch_processing.o conn_cruncher_stats.o

binaries = mptcpplot mptcpsplit mptcpcrunch
manfiles = $(binaries:=.1)

all: $(binaries)

mptcpplot: $(mptcpplot_objects)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(mptcpplot_objects) $(LDLIBS) -o $@

mptcpparser.o: mptcpparser.cc mptcpparser.h 
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c mptcpparser.cc

mptcpsplit: $(mptcpsplit_objects)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(mptcpsplit_objects) $(LDLIBS) -o $@

mptcpsplit.o: mptcpsplit.cc
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c mptcpsplit.cc

mptcpcrunch: $(mptcpcrunch_objects)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(mptcpcrunch_objects) $(LDLIBS) -o $@

conn_cruncher.o: conn_cruncher.cc conn_crunch_processing.o
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c conn_cruncher.cc

conn_crunch_processing.o: conn_crunch_processing.cc conn_crunch_processing.h layer_handlers.o four_tuple.o connection_map.o subflow.o
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c conn_crunch_processing.cc

layer_handlers.o: layer_handlers.cc layer_handlers.h four_tuple.o dss.o parser_utility.o
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c layer_handlers.cc

address.o: address.cc address.h parser_utility.o
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c address.cc

four_tuple.o: four_tuple.cc four_tuple.h address.o
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c four_tuple.cc

connection_map.o: connection_map.cc connection_map.h four_tuple.o layer_handlers.o
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c connection_map.cc

parser_utility.o: parser_utility.cc parser_utility.h
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c parser_utility.cc

mptcp_connection.o: mptcp_connection.cc mptcp_connection.h parser_utility.o four_tuple.o dss.o
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c mptcp_connection.cc

plotter.o: plotter.cc plotter.h dss.o four_tuple.o mptcp_connection.o parser_utility.o
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c plotter.cc

dss.o: dss.cc dss.h parser_utility.o
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c dss.cc

processing.o: processing.cc processing.h options.o connection_map.o mptcp_connection.o plotter.o layer_handlers.o four_tuple.o dss.o mapping.o
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c processing.cc

options.o: options.cc options.h
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c options.cc

mapping.o: mapping.cc mapping.h
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c mapping.cc

split_processing.o: split_processing.cc split_processing.h layer_handlers.o
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c split_processing.cc

subflow.o: subflow.cc subflow.h four_tuple.o
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c subflow.cc

conn_cruncher_stats.o: conn_cruncher_stats.cc conn_cruncher_stats.h conn_crunch_processing.o
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c conn_cruncher_stats.cc

.PHONY: all clean install uninstall

clean:
	-rm *.o $(binaries)

install: $(binaries)
	install -D -m 755 -t $(PREFIX)/bin $(binaries)
	install -D -m 644 -t $(PREFIX)/man/man1 $(addprefix man/, $(manfiles))

uninstall:
	-rm -fv $(addprefix $(PREFIX)/bin/, $(binaries))
	-rm -fv $(addprefix $(PREFIX)/man/man1/, $(manfiles))
