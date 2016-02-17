// (c)2007 Andy Green <andy@warmcat.com>

// commented by Jose Saldana. 2016

/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; version 2.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

// Thanks for contributions:
// 2007-03-15 fixes to getopt_long code by Matteo Croce rootkit85@yahoo.it

#include "packetspammer.h"
#include "radiotap.h"

/* wifi bitrate to use in 500kHz units */

static const u8 u8aRatesToUse[] = {

	54*2,
	48*2,
	36*2,
	24*2,
	18*2,
	12*2,
	9*2,
	11*2,
	11, // 5.5
	2*2,
	1*2
};

/* this is the template radiotap header we send packets out with */

static const u8 u8aRadiotapHeader[] = {	// the uxx types are "unsigned integers", of the specified bit widths
										// so u8 is a 8-bit unsigned integer

	0x00, // <-- radiotap version
	0x00, // <-- padding
	0x19, 0x00, // <- radiotap header length; 19 in hexadecimal means 25 bytes in decimal.
				// specified in little endian byte-order (i.e. inverse order)
	0x6f, 0x08, 0x00, 0x00, // <-- it_present bitmap Hex0000086F->bin 00000000 00000000 00001000 01101111
							//                                        ^                                 ^
	                        //                                        31                                0
							// the bit 31 non set (0) indicates that this is the only "it_present" word
							// these are the fields (see http://www.radiotap.org/defined-fields)
							// 1 TSFT
							// 1 Flags
							// 1 rate
							// 1 channel
							// 0 FHSS
							// 1 antenna signal
							// 1 antenna noise
							// 0 lock quality
							// 0 TX attenuation
							// 0 dB TX attenuation
							// 0 dBm TX power
							// 1 antenna
							// etc
	
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // <-- TSFT timestamp
	0x00, // <-- flags (Offset +0x10)
	0x6c, // <-- rate (0ffset +0x11)
	0x71, 0x09, 0xc0, 0x00, // <-- channel: mask 00c0 frequency hex0971=2417MHz
	0xde, // <-- antsignal
	0x00, // <-- antnoise
	0x01, // <-- antenna

};
#define	OFFSET_FLAGS 0x10
#define	OFFSET_RATE 0x11


/* Penumbra IEEE80211 header */
// this seems to be the IEEE802.11 header
static const u8 u8aIeeeHeader[] = {
	0x08, 0x01, 0x00, 0x00,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0x13, 0x22, 0x33, 0x44, 0x55, 0x66,
	0x13, 0x22, 0x33, 0x44, 0x55, 0x66,
	0x10, 0x86,
};


// this is the struct where we store a summary of the
// information from the radiotap header

typedef struct  {
	int m_nChannel;
	int m_nChannelFlags;
	int m_nRate;
	int m_nAntenna;
	int m_nRadiotapFlags;
} __attribute__((packed)) PENUMBRA_RADIOTAP_DATA;



int flagHelp = 0, flagMarkWithFCS = 0;


// dump the packet to the screen
void
Dump(u8 * pu8, int nLength)
{
	char sz[256], szBuf[512], szChar[17], *buf, fFirst = 1;
	unsigned char baaLast[2][16];
	uint n, nPos = 0, nStart = 0, nLine = 0, nSameCount = 0;

	buf = szBuf;
	szChar[0] = '\0';

	for (n = 0; n < nLength; n++) {
		baaLast[(nLine&1)^1][n&0xf] = pu8[n];
		if ((pu8[n] < 32) || (pu8[n] >= 0x7f))
			szChar[n&0xf] = '.';
		else
			szChar[n&0xf] = pu8[n];
		szChar[(n&0xf)+1] = '\0';
		nPos += sprintf(&sz[nPos], "%02X ",
			baaLast[(nLine&1)^1][n&0xf]);
		if ((n&15) != 15)
			continue;
		if ((memcmp(baaLast[0], baaLast[1], 16) == 0) && (!fFirst)) {
			nSameCount++;
		} else {
			if (nSameCount)
				buf += sprintf(buf, "(repeated %d times)\n",
					nSameCount);
			buf += sprintf(buf, "%04x: %s %s\n",
				nStart, sz, szChar);
			nSameCount = 0;
			printf("%s", szBuf);
			buf = szBuf;
		}
		nPos = 0; nStart = n+1; nLine++;
		fFirst = 0; sz[0] = '\0'; szChar[0] = '\0';
	}
	if (nSameCount)
		buf += sprintf(buf, "(repeated %d times)\n", nSameCount);

	buf += sprintf(buf, "%04x: %s", nStart, sz);
	if (n & 0xf) {
		*buf++ = ' ';
		while (n & 0xf) {
			buf += sprintf(buf, "   ");
			n++;
		}
	}
	buf += sprintf(buf, "%s\n", szChar);
	printf("%s", szBuf);
}


// print the usage info
void
usage(void)
{
	printf(
	    "(c)2006-2007 Andy Green <andy@warmcat.com>  Licensed under GPL2\n"
	    "\n"
	    "Usage: packetspammer [options] <interface>\n\nOptions\n"
	    "-d/--delay <delay> Delay between packets\n\n"
	    "-f/--fcs           Mark as having FCS (CRC) already\n"
	    "                   (pkt ends with 4 x sacrificial - chars)\n"
	    "Example:\n"
//	    "  echo -n mon0 > /sys/class/ieee80211/phy0/add_iface\n"	// this seems to be legacy
//	    "  iwconfig mon0 mode monitor\n" 							// this is already included in the next command
		"  iw phy phy0 interface add mon0 type monitor\n"
		"  iwconfig mon0 channel 6\n"
	    "  ifconfig mon0 up\n"
	    "  packetspammer mon0        Spam down mon0 with\n"
	    "                            radiotap header first\n"
	    "\n");
	exit(1);
}


int
main(int argc, char *argv[])
{
	u8 u8aSendBuffer[500];	// an array of unsigned integers of 8 bits
	char szErrbuf[PCAP_ERRBUF_SIZE];
	int nCaptureHeaderLength = 0, n80211HeaderLength = 0, nLinkEncap = 0;
	int nOrdinal = 0, r, nDelay = 100000;
	int nRateIndex = 0, retval, bytes;
	pcap_t *ppcap = NULL;
	struct bpf_program bpfprogram;
	char * szProgram = "", fBrokenSocket = 0;
	u16 u16HeaderLen;
	char szHostname[PATH_MAX];

	if (gethostname(szHostname, sizeof (szHostname) - 1)) {
		perror("unable to get hostname");
	}
	szHostname[sizeof (szHostname) - 1] = '\0';


	printf("Packetspammer (c)2007 Andy Green <andy@warmcat.com>  GPL2\n");

	while (1) {
		int nOptionIndex;
		static const struct option optiona[] = {
			{ "delay", required_argument, NULL, 'd' },
			{ "fcs", no_argument, &flagMarkWithFCS, 1 },
			{ "help", no_argument, &flagHelp, 1 },
			{ 0, 0, 0, 0 }
		};
		int c = getopt_long(argc, argv, "d:hf",
			optiona, &nOptionIndex);

		if (c == -1)
			break;
		switch (c) {
		case 0: // long option
			break;

		case 'h': // help
			usage();

		case 'd': // delay
			nDelay = atoi(optarg);
			break;

		case 'f': // mark as FCS attached
			flagMarkWithFCS = 1;
			break;

		default:
			printf("unknown switch %c\n", c);
			usage();
			break;
		}
	}

	if (optind >= argc)
		usage();


	// open the interface in pcap

	szErrbuf[0] = '\0';
	ppcap = pcap_open_live(argv[optind], 800, 1, 20, szErrbuf);
	if (ppcap == NULL) {
		printf("Unable to open interface %s in pcap: %s\n",
		    argv[optind], szErrbuf);
		return (1);
	}

	nLinkEncap = pcap_datalink(ppcap);
	nCaptureHeaderLength = 0;

	switch (nLinkEncap) {

		// it seems that Prism header is a legacy feature
		case DLT_PRISM_HEADER:
			printf("DLT_PRISM_HEADER Encap\n");
			nCaptureHeaderLength = 0x40;
			n80211HeaderLength = 0x20; // ieee80211 comes after this
			szProgram = "radio[0x4a:4]==0x13223344";
			break;

		case DLT_IEEE802_11_RADIO:
			printf("DLT_IEEE802_11_RADIO Encap\n");
			nCaptureHeaderLength = 0x40;
			n80211HeaderLength = 0x18; // ieee80211 comes after this
			szProgram = "ether[0x0a:4]==0x13223344";
			break;

		default:
			printf("!!! unknown encapsulation on %s !\n", argv[1]);
			return (1);

	}

	if (pcap_compile(ppcap, &bpfprogram, szProgram, 1, 0) == -1) {
		puts(szProgram);
		puts(pcap_geterr(ppcap));
		return (1);
	} else {
		if (pcap_setfilter(ppcap, &bpfprogram) == -1) {
			puts(szProgram);
			puts(pcap_geterr(ppcap));
		} else {
			printf("RX Filter applied\n");
		}
		pcap_freecode(&bpfprogram);
	}

	pcap_setnonblock(ppcap, 1, szErrbuf);

	printf("   (delay between packets %dus)\n", nDelay);

	memset(u8aSendBuffer, 0, sizeof (u8aSendBuffer));

	while (!fBrokenSocket) {
		u8 * pu8 = u8aSendBuffer;
		struct pcap_pkthdr * ppcapPacketHeader = NULL;
		struct ieee80211_radiotap_iterator rti;
		PENUMBRA_RADIOTAP_DATA prd;
		u8 * pu8Payload = u8aSendBuffer;
		int n, nRate;

		// receive

		retval = pcap_next_ex(ppcap, &ppcapPacketHeader,
		    (const u_char**)&pu8Payload);

		if (retval < 0) {
			fBrokenSocket = 1;
			continue;
		}

		if (retval != 1)
			goto do_tx;

		u16HeaderLen = (pu8Payload[2] + (pu8Payload[3] << 8));

		printf("rtap: ");
		Dump(pu8Payload, u16HeaderLen);

		if (ppcapPacketHeader->len <
		    (u16HeaderLen + n80211HeaderLength))
			continue;

		bytes = ppcapPacketHeader->len -
			(u16HeaderLen + n80211HeaderLength);
		if (bytes < 0)
			continue;

		if (ieee80211_radiotap_iterator_init(&rti,
		    (struct ieee80211_radiotap_header *)pu8Payload,
		    bytes) < 0)
			continue;

		while ((n = ieee80211_radiotap_iterator_next(&rti)) == 0) {

			switch (rti.this_arg_index) {
			case IEEE80211_RADIOTAP_RATE:
				prd.m_nRate = (*rti.this_arg);
				break;

			case IEEE80211_RADIOTAP_CHANNEL:
				prd.m_nChannel =
				    le16_to_cpu(*((u16 *)rti.this_arg));
				prd.m_nChannelFlags =
				    le16_to_cpu(*((u16 *)(rti.this_arg + 2)));
				break;

			case IEEE80211_RADIOTAP_ANTENNA:
				prd.m_nAntenna = (*rti.this_arg) + 1;
				break;

			case IEEE80211_RADIOTAP_FLAGS:
				prd.m_nRadiotapFlags = *rti.this_arg;
				break;

			}
		}

		pu8Payload += u16HeaderLen + n80211HeaderLength;

		if (prd.m_nRadiotapFlags & IEEE80211_RADIOTAP_F_FCS)
			bytes -= 4;

		printf("RX: Rate: %2d.%dMbps, Freq: %d.%dGHz, "
		    "Ant: %d, Flags: 0x%X\n",
		    prd.m_nRate / 2, 5 * (prd.m_nRate & 1),
		    prd.m_nChannel / 1000,
		    prd.m_nChannel - ((prd.m_nChannel / 1000) * 1000),
		    prd.m_nAntenna,
		    prd.m_nRadiotapFlags);

		Dump(pu8Payload, bytes);

	do_tx:

		// transmit

		memcpy(u8aSendBuffer, u8aRadiotapHeader,
			sizeof (u8aRadiotapHeader));
		if (flagMarkWithFCS)
			pu8[OFFSET_FLAGS] |= IEEE80211_RADIOTAP_F_FCS;
		nRate = pu8[OFFSET_RATE] = u8aRatesToUse[nRateIndex++];
		if (nRateIndex >= sizeof (u8aRatesToUse))
			nRateIndex = 0;
		pu8 += sizeof (u8aRadiotapHeader);

		memcpy(pu8, u8aIeeeHeader, sizeof (u8aIeeeHeader));
		pu8 += sizeof (u8aIeeeHeader);

		pu8 += sprintf((char *)pu8,
		    "Packetspammer %02d"
		    "broadcast packet"
		    "#%05d -- :-D --%s ----",
		    nRate/2, nOrdinal++, szHostname);
		
		// http://www.tcpdump.org/manpages/pcap_inject.3pcap.html
		// pcap_inject() sends a raw packet through the network 
		//  interface; buf points to the data of the packet, including 
		//  the link-layer header, and size is the number of bytes in the packet.
		r = pcap_inject(ppcap, u8aSendBuffer, pu8 - u8aSendBuffer);
		
		if (r != (pu8-u8aSendBuffer)) {
			perror("Trouble injecting packet");
			return (1);
		}
		if (nDelay)
			usleep(nDelay);
	}



	return (0);
}
