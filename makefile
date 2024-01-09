LDLIBS += -lpcap

all: airodump

pcap-test: airodump.c

clean:
	rm -f airodump *.o
