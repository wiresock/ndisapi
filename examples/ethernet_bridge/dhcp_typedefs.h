#pragma once

#include "stdint.h"
#include "iphlp.h"

/* options: */
#define DEFAULT_LEASE_TIME      (1 * 356 * 24 * 60 * 60) /* 1 year */
#define DEFAULT_SUBNET_MASK     "255.255.255.0"
//#define DEFAULT_SUBNET_MASK     "255.255.255.64"

enum { broadcast = 0xffffffff };

#ifndef s_addr
#define s_addr S_un.S_addr
#endif /* s_addr */

#ifndef INADDR_ANY
#define INADDR_ANY 0
#endif /* INADDR_ANY */

#define IPPORT_DHCPS            67
#define IPPORT_DHCPC            68

/* reference: http://tools.ietf.org/html/rfc2131 */

#define DHCP_UDP_OVERHEAD       (20 + /* IP header */                   \
                                8)   /* UDP header */
#define DHCP_ETHERNET_OVERHEAD  (14 +/* ETHERNET header */              \
                                20 + /* IP header */                    \
                                8)   /* UDP header */
#define DHCP_SNAME_LEN          64
#define DHCP_FILE_LEN           128
#define DHCP_FIXED_NON_UDP      236
#define DHCP_FIXED_LEN          (DHCP_FIXED_NON_UDP + DHCP_UDP_OVERHEAD)
                                            /* Everything but options. */
#define BOOTP_MIN_LEN           300

#define DHCP_MTU_MAX            1500
#define DHCP_MTU_MIN            576

#define DHCP_MAX_OPTION_LEN     (DHCP_MTU_MAX - DHCP_FIXED_LEN)
#define DHCP_MIN_OPTION_LEN     (DHCP_MTU_MIN - DHCP_FIXED_LEN)

/*
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     op (1)    |   htype (1)   |   hlen (1)    |   hops (1)    |
   +---------------+---------------+---------------+---------------+
   |                            xid (4)                            |
   +-------------------------------+-------------------------------+
   |           secs (2)            |           flags (2)           |
   +-------------------------------+-------------------------------+
   |                          ciaddr  (4)                          |
   +---------------------------------------------------------------+
   |                          yiaddr  (4)                          |
   +---------------------------------------------------------------+
   |                          siaddr  (4)                          |
   +---------------------------------------------------------------+
   |                          giaddr  (4)                          |
   +---------------------------------------------------------------+
   |                                                               |
   |                          chaddr  (16)                         |
   |                                                               |
   |                                                               |
   +---------------------------------------------------------------+
   |                                                               |
   |                          sname   (64)                         |
   +---------------------------------------------------------------+
   |                                                               |
   |                          file    (128)                        |
   +---------------------------------------------------------------+
   |                                                               |
   |                          options (variable)                   |
   +---------------------------------------------------------------+

*/

struct dhcp_packet {
  uint8_t        op;        /* Message op code / message type. 1 = BOOTREQUEST, 2 = BOOTREPLY */
  uint8_t        htype;     /* Hardware address type, see ARP section in "Assigned Numbers" RFC; e.g., '1' = 10mb ethernet. */
  uint8_t        hlen;      /* Hardware address length (e.g.  '6' for 10mb ethernet). */
  uint8_t        hops;      /* Client sets to zero, optionally used by relay agents when booting via a relay agent. */
  uint32_t       xid;       /* Transaction ID, a random number chosen by the client, used by the client and server to associate
                               messages and responses between a client and a server. */
  uint16_t       secs;      /* Filled in by client, seconds elapsed since client began address acquisition or renewal process. */
  uint16_t       flags;     /* Flags */
  struct in_addr ciaddr;    /* Client IP address; only filled in if client is in BOUND, RENEW or REBINDING state and can respond
                               to ARP requests.*/
  struct in_addr yiaddr;    /* 'your' (client) IP address. */
  struct in_addr siaddr;    /* IP address of next server to use in bootstrap; returned in DHCPOFFER, DHCPACK by server. */
  struct in_addr giaddr;    /* Relay agent IP address, used in booting via a relay agent. */
  uint8_t        chaddr[16];/* Client hardware (MAC) address. */ 
  char           sname[DHCP_SNAME_LEN]; 
                            /* Optional server host name, null terminated string. */
  char           file[DHCP_FILE_LEN]; 
                            /* Boot file name, null terminated string; "generic" name or null in DHCPDISCOVER, fully qualified
                               directory-path name in DHCPOFFER. */
  uint8_t        options[DHCP_MAX_OPTION_LEN]; 
                            /* Optional parameters, first bytes is magic numbers 99, 130, 83, 99 */
}; 

//#define dhcp_size (sizeof(ether_header) + sizeof(iphdr) + sizeof(udphdr) + sizeof(struct dhcp_packet))

/* BOOTP (rfc951) message types */
#define	BOOTREQUEST     1
#define BOOTREPLY       2

/* Possible values for flags field... */
#define BOOTP_BROADCAST 32768L

/* Possible values for hardware type (htype) field... */
#define HTYPE_ETHER     1               /* Ethernet 10Mbps              */
#define HTYPE_IEEE802   6               /* IEEE 802.2 Token Ring...     */
#define HTYPE_FDDI      8               /* FDDI...                      */

/* Magic cookie validating dhcp options field (and bootp vendor
   extensions field). */
#define DHCP_OPTIONS_COOKIE                     "\x63\x82\x53\x63"

#define DHCP_OPTIONS_OFFS (offsetof(struct dhcp_packet, options) + sizeof(DHCP_OPTIONS_COOKIE) - 1)

/* DHCP Option codes: */
#define DHO_PAD                                 0
#define DHO_SUBNET_MASK                         1
#define DHO_TIME_OFFSET                         2
#define DHO_ROUTERS                             3
#define DHO_TIME_SERVERS                        4
#define DHO_NAME_SERVERS                        5
#define DHO_DOMAIN_NAME_SERVERS                 6
#define DHO_LOG_SERVERS                         7
#define DHO_COOKIE_SERVERS                      8
#define DHO_LPR_SERVERS                         9
#define DHO_IMPRESS_SERVERS                     10
#define DHO_RESOURCE_LOCATION_SERVERS           11
#define DHO_HOST_NAME                           12
#define DHO_BOOT_SIZE                           13
#define DHO_MERIT_DUMP                          14
#define DHO_DOMAIN_NAME                         15
#define DHO_SWAP_SERVER                         16
#define DHO_ROOT_PATH                           17
#define DHO_EXTENSIONS_PATH                     18
#define DHO_IP_FORWARDING                       19
#define DHO_NON_LOCAL_SOURCE_ROUTING            20
#define DHO_POLICY_FILTER                       21
#define DHO_MAX_DGRAM_REASSEMBLY                22
#define DHO_DEFAULT_IP_TTL                      23
#define DHO_PATH_MTU_AGING_TIMEOUT              24
#define DHO_PATH_MTU_PLATEAU_TABLE              25
#define DHO_INTERFACE_MTU                       26
#define DHO_ALL_SUBNETS_LOCAL                   27
#define DHO_BROADCAST_ADDRESS                   28
#define DHO_PERFORM_MASK_DISCOVERY              29
#define DHO_MASK_SUPPLIER                       30
#define DHO_ROUTER_DISCOVERY                    31
#define DHO_ROUTER_SOLICITATION_ADDRESS         32
#define DHO_STATIC_ROUTES                       33
#define DHO_TRAILER_ENCAPSULATION               34
#define DHO_ARP_CACHE_TIMEOUT                   35
#define DHO_IEEE802_3_ENCAPSULATION             36
#define DHO_DEFAULT_TCP_TTL                     37
#define DHO_TCP_KEEPALIVE_INTERVAL              38
#define DHO_TCP_KEEPALIVE_GARBAGE               39
#define DHO_NIS_DOMAIN                          40
#define DHO_NIS_SERVERS                         41
#define DHO_NTP_SERVERS                         42
#define DHO_VENDOR_ENCAPSULATED_OPTIONS         43
#define DHO_NETBIOS_NAME_SERVERS                44
#define DHO_NETBIOS_DD_SERVER                   45
#define DHO_NETBIOS_NODE_TYPE                   46
#define DHO_NETBIOS_SCOPE                       47
#define DHO_FONT_SERVERS                        48
#define DHO_X_DISPLAY_MANAGER                   49
#define DHO_DHCP_REQUESTED_ADDRESS              50
#define DHO_DHCP_LEASE_TIME                     51
#define DHO_DHCP_OPTION_OVERLOAD                52
#define DHO_DHCP_MESSAGE_TYPE                   53
#define DHO_DHCP_SERVER_IDENTIFIER              54
#define DHO_DHCP_PARAMETER_REQUEST_LIST         55
#define DHO_DHCP_MESSAGE                        56
#define DHO_DHCP_MAX_MESSAGE_SIZE               57
#define DHO_DHCP_RENEWAL_TIME                   58
#define DHO_DHCP_REBINDING_TIME                 59
#define DHO_VENDOR_CLASS_IDENTIFIER             60
#define DHO_DHCP_CLIENT_IDENTIFIER              61
#define DHO_NWIP_DOMAIN_NAME                    62
#define DHO_NWIP_SUBOPTIONS                     63
#define DHO_USER_CLASS                          77
#define DHO_FQDN                                81
#define DHO_DHCP_AGENT_OPTIONS                  82
#define DHO_AUTHENTICATE                        90  /* RFC3118, was 210 */
#define DHO_CLIENT_LAST_TRANSACTION_TIME        91
#define DHO_ASSOCIATED_IP                       92
#define DHO_SUBNET_SELECTION                    118 /* RFC3011! */
#define DHO_DOMAIN_SEARCH                       119 /* RFC3397 */
#define DHO_VIVCO_SUBOPTIONS                    124
#define DHO_VIVSO_SUBOPTIONS                    125

#define DHO_END                                 255

/* DHCP message types. */
#define DHCPDISCOVER            1
#define DHCPOFFER               2
#define DHCPREQUEST             3
#define DHCPDECLINE             4
#define DHCPACK                 5
#define DHCPNAK                 6
#define DHCPRELEASE             7
#define DHCPINFORM              8
#define DHCPLEASEQUERY          10
#define DHCPLEASEUNASSIGNED     11
#define DHCPLEASEUNKNOWN        12
#define DHCPLEASEACTIVE         13

/* Relay Agent Information option subtypes: */
#define RAI_CIRCUIT_ID  1
#define RAI_REMOTE_ID   2
#define RAI_AGENT_ID    3
#define RAI_LINK_SELECT 5

/* FQDN suboptions: */
#define FQDN_NO_CLIENT_UPDATE           1
#define FQDN_SERVER_UPDATE              2
#define FQDN_ENCODED                    3
#define FQDN_RCODE1                     4
#define FQDN_RCODE2                     5
#define FQDN_HOSTNAME                   6
#define FQDN_DOMAINNAME                 7
#define FQDN_FQDN                       8
#define FQDN_SUBOPTION_COUNT            8

struct option {
  uint8_t code; 
  uint8_t len; 
  uint8_t *data; 
};

struct option_state {
  struct option *cache; 
  size_t count; 
};

/* A dhcp packet and the pointers to its option values. */
struct packet {
  struct dhcp_packet *raw; 
  size_t packet_length; 
  int packet_type; 

  bool options_valid; 
  struct in_addr client_addr; 
  uint16_t client_port; 
  struct ether_header hw;
  struct in_addr server_addr; 
  HANDLE hAdapter; 
  uint8_t direction;
  bool got_requested_address;

  struct option_state *options;
};

/* A dhcp lease declaration structure. */
struct lease {
  struct in_addr ip_addr; 
  struct in_addr subnet_addr; 
  struct in_addr subnet_mask; 
  struct in_addr dns_server; 
  time_t start; 
  time_t end; 
  char client_hostname[32];
};

/* [EOF] */
