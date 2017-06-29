PREFIX=/usr/local

mptcpplot_objects = mptcpparser.o layer_handlers.o address.o four_tuple.o connection_map.o parser_utility.o mptcp_connection.o plotter.o dss.o processing.o options.o mapping.o

mptcpsplit_objects = mptcpsplit.o layer_handlers.o address.o four_tuple.o connection_map.o parser_utility.o mptcp_connection.o plotter.o dss.o processing.o options.o mapping.o split_processing.o

mptcpcrunch_objects = conn_cruncher.o layer_handlers.o address.o four_tuple.o connection_map.o parser_utility.o mptcp_connection.o plotter.o dss.o processing.o options.o mapping.o split_processing.o subflow.o conn_crunch_processing.o conn_cruncher_stats.o

binaries = mptcpplot mptcpsplit mptcpcrunch
manfiles = $(binaries:=.1)

all: $(binaries)

mptcpplot: $(mptcpplot_objects)
	g++ -g -Wall $(mptcpplot_objects) -lpcap -lcrypto -lssl -o $@

mptcpparser.o: mptcpparser.cc mptcpparser.h 
	g++ -g -Wall -pedantic -c mptcpparser.cc

mptcpsplit: $(mptcpsplit_objects)
	g++ -g -Wall $(mptcpsplit_objects) -lpcap -lcrypto -lssl -o $@

mptcpsplit.o: mptcpsplit.cc
	g++ -g -Wall -pedantic -c mptcpsplit.cc

mptcpcrunch: $(mptcpcrunch_objects)
	g++ -g -Wall $(mptcpcrunch_objects) -lpcap -lcrypto -lssl -o $@

conn_cruncher.o: conn_cruncher.cc conn_crunch_processing.o
	g++ -g -Wall -pedantic -c conn_cruncher.cc

conn_crunch_processing.o: conn_crunch_processing.cc conn_crunch_processing.h layer_handlers.o four_tuple.o connection_map.o subflow.o
	g++ -g -Wall -pedantic -c conn_crunch_processing.cc

layer_handlers.o: layer_handlers.cc layer_handlers.h four_tuple.o dss.o parser_utility.o
	g++ -g -Wall -pedantic -c layer_handlers.cc

address.o: address.cc address.h parser_utility.o
	g++ -g -Wall -pedantic -c address.cc

four_tuple.o: four_tuple.cc four_tuple.h address.o
	g++ -g -Wall -pedantic -c four_tuple.cc

connection_map.o: connection_map.cc connection_map.h four_tuple.o layer_handlers.o
	g++ -g -Wall -pedantic -c connection_map.cc

parser_utility.o: parser_utility.cc parser_utility.h
	g++ -g -Wall -pedantic -c parser_utility.cc

mptcp_connection.o: mptcp_connection.cc mptcp_connection.h parser_utility.o four_tuple.o dss.o
	g++ -g -Wall -pedantic -c mptcp_connection.cc

plotter.o: plotter.cc plotter.h dss.o four_tuple.o mptcp_connection.o parser_utility.o
	g++ -g -Wall -pedantic -c plotter.cc

dss.o: dss.cc dss.h parser_utility.o
	g++ -g -Wall -pedantic -c dss.cc

processing.o: processing.cc processing.h options.o connection_map.o mptcp_connection.o plotter.o layer_handlers.o four_tuple.o dss.o mapping.o
	g++ -g -Wall -pedantic -c processing.cc

options.o: options.cc options.h
	g++ -g -Wall -pedantic -c options.cc

mapping.o: mapping.cc mapping.h
	g++ -g -Wall -pedantic -c mapping.cc

split_processing.o: split_processing.cc split_processing.h layer_handlers.o
	g++ -g -Wall -pedantic -c split_processing.cc

subflow.o: subflow.cc subflow.h four_tuple.o
	g++ -g -Wall -pedantic -c subflow.cc

conn_cruncher_stats.o: conn_cruncher_stats.cc conn_cruncher_stats.h conn_crunch_processing.o
	g++ -g -Wall -pedantic -c conn_cruncher_stats.cc

.PHONY: all clean install uninstall

clean:
	-rm *.o $(binaries)

install: $(binaries)
	install -D -m 755 -t $(PREFIX)/bin $(binaries)
	install -D -m 644 -t $(PREFIX)/man/man1 $(addprefix man/, $(manfiles))

uninstall:
	-rm -fv $(addprefix $(PREFIX)/bin/, $(binaries))
	-rm -fv $(addprefix $(PREFIX)/man/man1/, $(manfiles))
