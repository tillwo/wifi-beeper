/*
 *  Beeper - Make WLAN frames audible
 *
 *  Copyright (C) 2015 Till Wollenberg <till *dot* wollenberg *at* uni-rostock *dot* de>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/kd.h>
#include <ctype.h>
#include <net/if.h>
#include <signal.h>
#include <pcap/pcap.h>
#include "radiotap_iter.h"
#include "endian.h"

/* uclibc's pcap.h misses this definition */
#ifndef PCAP_NETMASK_UNKNOWN
#define PCAP_NETMASK_UNKNOWN    0xffffffff
#endif

#ifndef CLOCK_TICK_RATE
#define CLOCK_TICK_RATE 1193180
#endif

typedef struct {
	uint8_t b[6];
} __attribute__((packed)) mac_t;

static pcap_t *pcap;
static volatile int frames_received;

static int count;
static int signal_count;
static int signal_value;

static int console_fd;

/*
 * Test if str is a valid MAC address
 * (code taken from BlueZ's lib/bluetooth.c)
 */
static int check_mac(const char *str)
{
	if (!str)
		return -1;

	if (strlen(str) != 17)
		return -1;

	while (*str) {
		if (!isxdigit(*str++))
			return -1;

		if (!isxdigit(*str++))
			return -1;

		if (*str == 0)
			break;

		if (*str++ != ':')
			return -1;
	}

	return 0;
}

/*
 * Convert MAC address given as string to byte array.
 * (code based on BlueZ's lib/bluetooth.c)
 */
static int strtomac(const char *str, mac_t *mac)
{
	int i;

	if (check_mac(str) < 0) {
		memset(mac, 0, sizeof(mac_t));
		return -1;
	}

	for (i = 0; i < 6; i++, str += 3) {
		mac->b[i] = strtol(str, NULL, 16);
	}

	return 0;
}

static void sigint(int sig)
{
	fprintf(stderr, "\nReceived SIGINT.\n");
	pcap_breakloop(pcap);
}

static void print_usage()
{
#define STRINGIFY_HELPER(x) #x
#define STRINGIFY(x) STRINGIFY_HELPER(x)
	fprintf(stderr,
		"beeper " STRINGIFY(VERSION) "\n"
		"Usage:\n"
		" beeper <options> <source MAC address>\n"
		"  -I <device>    device to use (mandatory, device must be in monitor mode)\n"
		"  -c <count>     expected frames/second to estimate PRR (optional, default = 10)\n"
	);
}

static void beep(int frequency, int duration_ms)
{
	if ((console_fd > -1) && (ioctl(console_fd, KIOCSOUND, (int)(CLOCK_TICK_RATE / frequency)) == 0)) {
		usleep(1000 * duration_ms);
		ioctl(console_fd, KIOCSOUND, 0);
	}
}

static void nobeep()
{
	if (console_fd > -1) {
		ioctl(console_fd, KIOCSOUND, 0);
	}
}

static void packet_handler(u_char *user, const struct pcap_pkthdr *hdr, const u_char *packet)
{
	struct ieee80211_radiotap_iterator iter;
	struct ieee80211_radiotap_vendor_namespaces vns;
	int signal;
	
	frames_received++;
	
	vns.n_ns = 0;
	if (ieee80211_radiotap_iterator_init(&iter,
		(struct ieee80211_radiotap_header*) packet, hdr->caplen, &vns) == 0) {
		while (ieee80211_radiotap_iterator_next(&iter) == 0) {
			if ((iter.this_arg_index == IEEE80211_RADIOTAP_DBM_ANTSIGNAL) && (iter.this_arg_size >= 1)) {
				signal = (char)(*iter.this_arg);
				signal_value += signal;
				signal_count++;
				
				if (signal < -96) {
					signal = -96;
				}
				if (signal > -20) {
					signal = -20;
				}
				beep(100 + (signal + 96) * 52, 10);
			}
		}
	}
}

static void sigalrm(int sig)
{
	printf(
		"\33[2K\r"
		"%d frames_received (PRR %.1f%%)", frames_received, (frames_received / (double)count * 100.0)
	);
	
	if (signal_count > 0) {
		printf(" Average signal: %.1f dBm (from %d frames).",
			signal_value / (double)signal_count, signal_count);
	}
	else {
		printf(" No signal information.");
	}
	
	fflush(stdout);
	
	frames_received = 0;
	signal_count = 0;
	signal_value = 0;
}

int main (int argc, char *argv[])
{
	char ifname[IFNAMSIZ];
	int interval;
	mac_t source;
	char source_str[18];
	int c;
	char errbuf[PCAP_ERRBUF_SIZE];
	char filter[256];
	struct bpf_program fp;
	int linktype;
	struct itimerval itv;
	
	/*
	 * Default values
	 */
	ifname[0] = '\0';
	count = 10;         /* -1 == invalid */
	interval = 1000000; /* update interval in microseconds */
	
	/*
	 * Parse command line arguments
	 */
	opterr = 0;
	while ((c = getopt(argc, argv, ":I:c:")) != -1) {
		switch (c) {
			case 'I':
				if (strlen(optarg) < IFNAMSIZ) {
					strncpy(ifname, optarg, IFNAMSIZ);
				}
				else {
					fprintf(stderr, "'%s' is not a valid interface name\n", optarg);
					return -1;
				}
				break;

			case 'c':
				count = strtol(optarg, NULL, 10);
				if (count <= 0) {
					fprintf(stderr, "Count must be greater than 0.\n");
					return -1;
				}
				break;

			case ':':
				fprintf(stderr, "Option -%c requires an argument.\n", optopt);
				print_usage();
				return -1;

			case '?':
				fprintf(stderr, "Invalid option: -%c\n", optopt);
				print_usage();
				return -1;

			default:
				abort();
		}
	}     
	
	if (optind < argc) {
		if (strtomac(argv[optind], &source) < 0) {
			fprintf(stderr, "'%s' is not a valid MAC address.\n", argv[optind]);
			return -1;
		}
	}
	else {
		fprintf(stderr, "No destination specified.\n");
		print_usage();
		return -1;
	}
	
	if (strlen(ifname) == 0) {
		fprintf(stderr, "You have to specify which interface to use (see -I option).\n");
		return -1;
	}
	
	sprintf(source_str, "%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X", 
		source.b[0], source.b[1], source.b[2], source.b[3], source.b[4], source.b[5]);
	
	/*
	 * Open console (used for generating beeps)
	 */
	console_fd = open("/dev/console", O_WRONLY);
	if (console_fd == -1) {
		fprintf(stderr, "Could not open /dev/console for writing; beeps disabled.\n");
	}
	
	/*
	 * PCAP initialization
	 */
	errbuf[0] = '\0';
	pcap = pcap_open_live(ifname, 80, 1, 0, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "Unable to open interface: %s\n", errbuf);
		return 1;
	}
	
	linktype = pcap_datalink(pcap);
	if (linktype != DLT_IEEE802_11_RADIO) {
		fprintf(stderr, "Unsupported link type (%s) on %s, terminating.\n",
		                pcap_datalink_val_to_name(linktype), ifname);
		pcap_close(pcap);
		return 1;
	}

	/* Build filter that matches only beacon frames sent from the selected address */
	snprintf(filter, sizeof(filter),
			"(link[0] == 0x80)"            /* type/subtype == management/beacon */
			" and ((link[1] & 0x01)=0x00)" /* frods == 0, redundant for beacons, but will be needed later for data frames */
			" and link[10]=0x%2.2x and link[11]=0x%2.2x and link[12]=0x%2.2x"
			" and link[13]=0x%2.2x and link[14]=0x%2.2x and link[15]=0x%2.2x",
			source.b[0], source.b[1], source.b[2],
			source.b[3], source.b[4], source.b[5]
	);

	if (pcap_compile(pcap, &fp, filter, 1, PCAP_NETMASK_UNKNOWN) < 0) {
		fprintf(stderr, "Error compiling the pcap filter: %s.\n", pcap_geterr(pcap));
		return 1;
	}

	if (pcap_setfilter(pcap, &fp) < 0) {
		fprintf(stderr, "Error setting pcap filter: %s.\n", pcap_geterr(pcap));
		return 1;
	}

	/*
	 * Main loop
	 */
	signal(SIGINT, sigint);
	signal(SIGALRM, sigalrm);
	
	itv.it_value.tv_sec = (interval / 1000000);
	itv.it_value.tv_usec = (interval % 1000000);
	itv.it_interval.tv_sec = itv.it_value.tv_sec;
	itv.it_interval.tv_usec = itv.it_value.tv_usec; 
	
	signal_count = 0;
	signal_value = 0;
	
	if (setitimer(ITIMER_REAL, &itv, NULL) != 0) {
		fprintf(stderr, "setitimer() failed (%s)\n", strerror(errno));
		return -1;
	}
	
	if (pcap_loop(pcap, 0, packet_handler, NULL) != -2) {
		fprintf(stderr, "Error in pcap_loop().\n");
	}
	
	nobeep();
	close(console_fd);
	fprintf(stderr, "Terminated.\n");
	
	return 0;
}
