#pragma once
#include <ostream>

namespace pcap
{
	enum link_layer_type: uint32_t
	{
		/** BSD loopback encapsulation */
		LINKTYPE_NULL = 0,
		/** IEEE 802.3 Ethernet */
		LINKTYPE_ETHERNET = 1,
		/** AX.25 packet */
		LINKTYPE_AX25 = 3,
		/** IEEE 802.5 Token Ring */
		LINKTYPE_IEEE802_5 = 6,
		/** ARCNET Data Packets */
		LINKTYPE_ARCNET_BSD = 7,
		/** SLIP, encapsulated with a LINKTYPE_SLIP header */
		LINKTYPE_SLIP = 8,
		/** PPP, as per RFC 1661 and RFC 1662 */
		LINKTYPE_PPP = 9,
		/** FDDI, as specified by ANSI INCITS 239-1994 */
		LINKTYPE_FDDI = 10,
		/** Raw IP */
		LINKTYPE_DLT_RAW1 = 12,
		/** Raw IP (OpenBSD) */
		LINKTYPE_DLT_RAW2 = 14,
		/** PPP in HDLC-like framing, as per RFC 1662, or Cisco PPP with HDLC framing, as per section 4.3.1 of RFC 1547 */
		LINKTYPE_PPP_HDLC = 50,
		/** PPPoE */
		LINKTYPE_PPP_ETHER = 51,
		/** RFC 1483 LLC/SNAP-encapsulated ATM */
		LINKTYPE_ATM_RFC1483 = 100,
		/** Raw IP */
		LINKTYPE_RAW = 101,
		/** Cisco PPP with HDLC framing */
		LINKTYPE_C_HDLC = 104,
		/** IEEE 802.11 wireless LAN */
		LINKTYPE_IEEE802_11 = 105,
		/** Frame Relay */
		LINKTYPE_FRELAY = 107,
		/** OpenBSD loopback encapsulation */
		LINKTYPE_LOOP = 108,
		/** Linux "cooked" capture encapsulation */
		LINKTYPE_LINUX_SLL = 113,
		/** Apple LocalTalk */
		LINKTYPE_LTALK = 114,
		/** OpenBSD pflog */
		LINKTYPE_PFLOG = 117,
		/** Prism monitor mode information followed by an 802.11 header */
		LINKTYPE_IEEE802_11_PRISM = 119,
		/** RFC 2625 IP-over-Fibre Channel */
		LINKTYPE_IP_OVER_FC = 122,
		/** ATM traffic, encapsulated as per the scheme used by SunATM devices */
		LINKTYPE_SUNATM = 123,
		/** Radiotap link-layer information followed by an 802.11 header */
		LINKTYPE_IEEE802_11_RADIOTAP = 127,
		/** ARCNET Data Packets, as described by the ARCNET Trade Association standard ATA 878.1-1999 */
		LINKTYPE_ARCNET_LINUX = 129,
		/** Apple IP-over-IEEE 1394 cooked header */
		LINKTYPE_APPLE_IP_OVER_IEEE1394 = 138,
		/** Signaling System 7 Message Transfer Part Level 2 */
		LINKTYPE_MTP2_WITH_PHDR = 139,
		/** Signaling System 7 Message Transfer Part Level 2 */
		LINKTYPE_MTP2 = 140,
		/** Signaling System 7 Message Transfer Part Level 3 */
		LINKTYPE_MTP3 = 141,
		/** Signaling System 7 Signalling Connection Control Part */
		LINKTYPE_SCCP = 142,
		/** Signaling System 7 Signalling Connection Control Part */
		LINKTYPE_DOCSIS = 143,
		/** Linux-IrDA packets */
		LINKTYPE_LINUX_IRDA = 144,
		/** AVS monitor mode information followed by an 802.11 header */
		LINKTYPE_IEEE802_11_AVS = 163,
		/** BACnet MS/TP frames */
		LINKTYPE_BACNET_MS_TP = 165,
		/** PPP in HDLC-like encapsulation, like LINKTYPE_PPP_HDLC, but with the 0xff address byte replaced by a direction indication - 0x00 for incoming and 0x01 for outgoing */
		LINKTYPE_PPP_PPPD = 166,
		/** General Packet Radio Service Logical Link Control */
		LINKTYPE_GPRS_LLC = 169,
		/** Transparent-mapped generic framing procedure */
		LINKTYPE_GPF_T = 170,
		/** Frame-mapped generic framing procedure */
		LINKTYPE_GPF_F = 171,
		/** Link Access Procedures on the D Channel (LAPD) frames */
		LINKTYPE_LINUX_LAPD = 177,
		/** Bluetooth HCI UART transport layer */
		LINKTYPE_BLUETOOTH_HCI_H4 = 187,
		/** USB packets, beginning with a Linux USB header */
		LINKTYPE_USB_LINUX = 189,
		/** Per-Packet Information information */
		LINKTYPE_PPI = 192,
		/** IEEE 802.15.4 wireless Personal Area Network */
		LINKTYPE_IEEE802_15_4 = 195,
		/** Various link-layer types, with a pseudo-header, for SITA */
		LINKTYPE_SITA = 196,
		/** Various link-layer types, with a pseudo-header, for Endace DAG cards; encapsulates Endace ERF record */
		LINKTYPE_ERF = 197,
		/** Bluetooth HCI UART transport layer */
		LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR = 201,
		/** AX.25 packet, with a 1-byte KISS header containing a type indicator */
		LINKTYPE_AX25_KISS = 202,
		/** Link Access Procedures on the D Channel (LAPD) frames */
		LINKTYPE_LAPD = 203,
		/** PPP, as per RFC 1661 and RFC 1662, preceded with a one-byte pseudo-header with a zero value meaning "received by this host" and a non-zero value meaning  "sent by this host" */
		LINKTYPE_PPP_WITH_DIR = 204,
		/** Cisco PPP with HDLC framing */
		LINKTYPE_C_HDLC_WITH_DIR = 205,
		/** Frame Relay */
		LINKTYPE_FRELAY_WITH_DIR = 206,
		/** IPMB over an I2C circuit */
		LINKTYPE_IPMB_LINUX = 209,
		/** IEEE 802.15.4 wireless Personal Area Network */
		LINKTYPE_IEEE802_15_4_NONASK_PHY = 215,
		/** USB packets, beginning with a Linux USB header */
		LINKTYPE_USB_LINUX_MMAPPED = 220,
		/** Fibre Channel FC-2 frames, beginning with a Frame_Header */
		LINKTYPE_FC_2 = 224,
		/** Fibre Channel FC-2 frames */
		LINKTYPE_FC_2_WITH_FRAME_DELIMS = 225,
		/** Solaris ipnet pseudo-header */
		LINKTYPE_IPNET = 226,
		/** CAN (Controller Area Network) frames, with a pseudo-header as supplied by Linux SocketCAN */
		LINKTYPE_CAN_SOCKETCAN = 227,
		/** Raw IPv4; the packet begins with an IPv4 header */
		LINKTYPE_IPV4 = 228,
		/** Raw IPv6; the packet begins with an IPv6 header */
		LINKTYPE_IPV6 = 229,
		/** IEEE 802.15.4 wireless Personal Area Network, without the FCS at the end of the frame */
		LINKTYPE_IEEE802_15_4_NOFCS = 230,
		/** Raw D-Bus messages, starting with the endianness flag, followed by the message type, etc., but without the authentication handshake before the message sequence */
		LINKTYPE_DBUS = 231,
		/** DVB-CI (DVB Common Interface for communication between a PC Card module and a DVB receiver), with the message format specified by the PCAP format for DVB-CI specification */
		LINKTYPE_DVB_CI = 235,
		/** Variant of 3GPP TS 27.010 multiplexing protocol (similar to, but not the same as, 27.010) */
		LINKTYPE_MUX27010 = 236,
		/** D_PDUs as described by NATO standard STANAG 5066, starting with the synchronization sequence, and including both header and data CRCs */
		LINKTYPE_STANAG_5066_D_PDU = 237,
		/** Linux netlink NETLINK NFLOG socket log messages */
		LINKTYPE_NFLOG = 239,
		/** Pseudo-header for Hilscher Gesellschaft für Systemautomation mbH netANALYZER devices, followed by an Ethernet frame, beginning with the MAC header and ending with the FCS */
		LINKTYPE_NETANALYZER = 240,
		/** Pseudo-header for Hilscher Gesellschaft für Systemautomation mbH netANALYZER devices, followed by an Ethernet frame, beginning with the preamble, SFD, and MAC header, and ending with the FCS */
		LINKTYPE_NETANALYZER_TRANSPARENT = 241,
		/** IP-over-InfiniBand, as specified by RFC 4391 section 6 */
		LINKTYPE_IPOIB = 242,
		/** MPEG-2 Transport Stream transport packets, as specified by ISO 13818-1/ITU-T Recommendation H.222.0 */
		LINKTYPE_MPEG_2_TS = 243,
		/** Pseudo-header for ng4T GmbH's UMTS Iub/Iur-over-ATM and Iub/Iur-over-IP format as used by their ng40 protocol tester */
		LINKTYPE_NG40 = 244,
		/** Pseudo-header for NFC LLCP packet captures, followed by frame data for the LLCP Protocol as specified by NFCForum-TS-LLCP_1.1 */
		LINKTYPE_NFC_LLCP = 245,
		/** Raw InfiniBand frames, starting with the Local Routing Header */
		LINKTYPE_INFINIBAND = 247,
		/** SCTP packets, as defined by RFC 4960, with no lower-level protocols such as IPv4 or IPv6 */
		LINKTYPE_SCTP = 248,
		/** USB packets, beginning with a USBPcap header */
		LINKTYPE_USBPCAP = 249,
		/** Serial-line packet header for the Schweitzer Engineering Laboratories "RTAC" product */
		LINKTYPE_RTAC_SERIAL = 250,
		/** Bluetooth Low Energy air interface Link Layer packets */
		LINKTYPE_BLUETOOTH_LE_LL = 251,
		/** Linux Netlink capture encapsulation */
		LINKTYPE_NETLINK = 253,
		/** Bluetooth Linux Monitor encapsulation of traffic for the BlueZ stack */
		LINKTYPE_BLUETOOTH_LINUX_MONITOR = 254,
		/** Bluetooth Basic Rate and Enhanced Data Rate baseband packets */
		LINKTYPE_BLUETOOTH_BREDR_BB = 255,
		/** Bluetooth Low Energy link-layer packets */
		LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR = 256,
		/** PROFIBUS data link layer packets, as specified by IEC standard 61158-6-3 */
		LINKTYPE_PROFIBUS_DL = 257,
		/** Apple PKTAP capture encapsulation */
		LINKTYPE_PKTAP = 258,
		/** Ethernet-over-passive-optical-network packets */
		LINKTYPE_EPON = 259,
		/** IPMI trace packets, as specified by Table 3-20 "Trace Data Block Format" in the PICMG HPM.2 specification */
		LINKTYPE_IPMI_HPM_2 = 260,
		/** Per Joshua Wright <jwright@hasborg.com>, formats for Z-Wave RF profiles R1 and R2 captures */
		LINKTYPE_ZWAVE_R1_R2 = 261,
		/** Per Joshua Wright <jwright@hasborg.com>, formats for Z-Wave RF profile R3 captures */
		LINKTYPE_ZWAVE_R3 = 262,
		/** Formats for WattStopper Digital Lighting Management (DLM) and Legrand Nitoo Open protocol common packet structure captures */
		LINKTYPE_WATTSTOPPER_DLM = 263,
		/** Messages between ISO 14443 contactless smartcards (Proximity Integrated Circuit Card, PICC) and card readers (Proximity Coupling Device, PCD), with the message format specified by the PCAP format for ISO14443 specification */
		LINKTYPE_ISO_14443 = 264
	};

	typedef struct pcap_hdr_s {
		uint32_t magic_number;   /* magic number */
		uint16_t version_major;  /* major version number */
		uint16_t version_minor;  /* minor version number */
		int32_t  thiszone;       /* GMT to local correction */
		uint32_t sigfigs;        /* accuracy of timestamps */
		uint32_t snaplen;        /* max length of captured packets, in octets */
		uint32_t network;        /* data link type */
	} pcap_hdr_t;

	typedef struct pcaprec_hdr_s {
		uint32_t ts_sec;         /* timestamp seconds */
		uint32_t ts_usec;        /* timestamp microseconds */
		uint32_t incl_len;       /* number of octets of packet saved in file */
		uint32_t orig_len;       /* actual length of packet */
	} pcaprec_hdr_t;


	class pcap_file_header
	{
	public:
		pcap_file_header(const uint16_t version_major, const uint16_t version_minor, const int32_t this_zone, const uint32_t sig_figs,
			const uint32_t snap_len, const link_layer_type network)
			: header_{ 0xa1b2c3d4, version_major, version_minor, this_zone, sig_figs, snap_len, network }
		{
		}

		friend std::ostream& operator<<(std::ostream& os, const pcap_file_header& obj)
		{
			return os.write(reinterpret_cast<const char*>(&obj.header_), sizeof(pcap_hdr_t));
		}

	private:
		pcap_hdr_t header_;
	};

	class pcap_record_header
	{
	public:
		pcap_record_header(const uint32_t timestamp_sec, const uint32_t timestamp_usec, const uint32_t incl_len, const uint32_t orig_len, char const* data)
			: header_{ timestamp_sec, timestamp_usec, incl_len, orig_len }, data_{ data }
		{
		}

		friend std::ostream& operator<<(std::ostream& os, const pcap_record_header& obj)
		{
			return os.write(reinterpret_cast<const char*>(&obj.header_), sizeof(pcaprec_hdr_t)).write(obj.data_, obj.header_.incl_len);
		}

	private:
		pcaprec_hdr_t header_;
		char const* data_;
	};
}