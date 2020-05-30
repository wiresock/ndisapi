/*************************************************************************/
/*				Copyright (c) 2000-2016 NT Kernel Resources.		     */
/*                           All Rights Reserved.                        */
/*                          http://www.ntkernel.com                      */
/*                           ndisrd@ntkernel.com                         */
/* Module Name:  NetworkInterface.h		                                 */
/*                                                                       */
/* Abstract: CNetworkInterface declaration		      	                 */
/*                                                                       */
/*                                                                       */
/*************************************************************************/

#pragma once
#include <afxtempl.h>
#include "ipexport.h"

// We keep IP addresses in this structure to avoid unnecessary
// conversions
class CIpAddr
{
public:
	CString m_szIp;
	CString m_szMask;
	in_addr m_Ip;
};

// Possible interface states
// NONE - adapter works usual
// PROVIDER - this interface connection is shared by all connections configured as CLIENT (usually Internet connection interface)
// CLIENT - usually interface in the home network
typedef enum
{
	NONE,
	PROVIDER,
	CLIENT
} NAT_STATUS;

// CIpAddrList is used for keeping all IP's associated with network interface
typedef CTypedPtrList<CPtrList, CIpAddr*> CIpAddrList;

struct CNetworkInterface
{
	CNetworkInterface(void);
	~CNetworkInterface(void);

	CString			m_szInternalName; // Internal interface name (as it is seen by WinpkFilter driver)
	CString			m_szUserFriendlyName; // User friendly interface (network connection) name as it is seen in Network Connections
	bool			m_bIsWan; // TRUE for WAN (dial-up) interfaces
	unsigned char	m_chMACAddr[ETHER_ADDR_LENGTH]; // MAC (Ethernet) address for the network interface
	CIpAddrList		m_IpList; // List of configured IP addresses
	NAT_STATUS		m_NATState; // NONE, PROVIDER or CLIENT (see description above)
	in_addr			m_NATIp; // IP address used for NAT'ing (makes sense only if adapter configured as PROVIDER)
	HANDLE			m_hAdapter; // Network interface handle (required for any operations using WinpkFilter driver)
	in_addr			m_LocalDNS; // Used for redirecting DNS requests, usually should be equal to the one of the interfcae local IP's
								// makes sense only for adapters configured as CLIENT
	DWORD			m_Index;	//Index of this interface 
	USHORT			m_MTU;		//MTU of this interface

	BOOL	IsLocalAddress (in_addr* pIp); // Returns TRUE is specified IP belongs (configured) to this network interface
	int		InitIPInformation (void); // Initializes IP address list for this interface though IP helper API
	void	InitMTUInformation(void); //Initializes MTU information for this interface
};

// Type for list of network interfaces
typedef CTypedPtrList<CPtrList, CNetworkInterface*> CNetworkInterfacesList;

