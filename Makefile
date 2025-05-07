LDLIBS = -lnetfilter_queue
 

all: netfilter-test

netfilter-test: main.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f netfilter-test *.o