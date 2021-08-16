#pragma once

namespace proxy
{
#pragma pack(push,1)
	struct socks5_ident_req
	{
		unsigned char version;
		unsigned char number_of_methods;
		unsigned char methods[ANY_SIZE];
	};

	struct socks5_ident_resp
	{
		unsigned char version;
		unsigned char method;
	};

	struct socks5_req
	{
		unsigned char version;
		unsigned char cmd;
		unsigned char reserved;
		unsigned char address_type;
		union {
			in_addr ip_v4;
			//	in6_addr ip_v6;
			//	struct {
			//		unsigned char domain_len;
			//		char domain[256];
			//	};
		} dest_address;
		unsigned short dest_port;
	};

	struct socks5_resp
	{
		unsigned char version;
		unsigned char reply;
		unsigned char reserved;
		unsigned char address_type;
		union {
			in_addr ip_v4;
			//in6_addr ip_v6;
			//struct {
			//	unsigned char domain_len;
			//	char domain[256];
			//};
		} bind_address;
		unsigned short bind_port;
	};

	struct socks5_udp_header
	{
		unsigned short reserved;
		unsigned char fragment;
		unsigned char address_type;
		union {
			in_addr ip_v4;
			//in6_addr ip_v6;
			//struct {
			//	unsigned char domain_len;
			//	char domain[256];
			//};
		} dest_address;
		unsigned short dest_port;
	};
#pragma pack(pop)
}