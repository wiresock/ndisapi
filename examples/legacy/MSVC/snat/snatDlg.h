/*************************************************************************/
/*				Copyright (c) 2000-2016 NT Kernel Resources.		     */
/*                           All Rights Reserved.                        */
/*                          http://www.ntkernel.com                      */
/*                           ndisrd@ntkernel.com                         */
/* Module Name:  snatDlg.h				                                 */
/*                                                                       */
/* Abstract: CsnatDlg dialog and NAT tables declarations                 */
/*                                                                       */
/*                                                                       */
/*************************************************************************/

#pragma once
#include "afxcmn.h"
#include "NetworkInterface.h"
#include "netcardprop.h"
#include "ipexport.h"
#include "iphlp.h"

#define NAT_TABLE_SIZE 256*256 // Size of NAT table
#define NAT_TIMEOUT 600 //This is timeout in seconds for which we keep the inactive entry in the NAT table until removal (10 minutes)
#define MAX_STRING 512
// CNATEntry describes single NAT entry
struct CNATEntry
{
	CNATEntry();
	in_addr			m_IpSrc;	// Source IP address
	in_addr			m_IpDst;	// Destination IP address
	in_addr			m_IpNAT;	// IP for NAT

	ULARGE_INTEGER	m_ulTimeStamp; // Last packet this entry was applied to
 
	CNATEntry*		prevEntry; // Previous NAT entry
	CNATEntry*		nextEntry; // Next NAT entry
};

// Describes single UDP/TCP NAT entry
struct CPortNATEntry: public CNATEntry
{
	CPortNATEntry();
	unsigned short m_usSrcPort; // Source port address
	unsigned short m_usDstPort; // Destination port address
	unsigned short m_usNATPort; // Port for NAT
};

// TCP/UDP NAT table
class CPortNATTable
{
	// Hash table for TCP connections
	CPortNATEntry**		m_Table; // Used for allocating and searching NAT entries for outgoing packets
	CPortNATEntry**		m_PortTable; // Used for mapping incoming packets to NAT entries
public:
	CPortNATTable ();
	~CPortNATTable ();

	// Outgoing NAT methods
	CPortNATEntry* Allocate (in_addr ip_src, unsigned short port_src, in_addr ip_dst, unsigned short port_dst);
	CPortNATEntry* Find (in_addr ip_src, unsigned short port_src, in_addr ip_dst, unsigned short port_dst);

	// Incoming NAT methods
	CPortNATEntry* Map (unsigned short port_dst);

	// Deleting entries methods
	void Free(CPortNATEntry* pNE);
	void RemoveAll();
};

// Describes single ICMP NAT entry
struct CIcmpNATEntry: public CNATEntry
{
	CIcmpNATEntry();
	unsigned short m_usIcmpId;		// Original ICMP ID
	unsigned short m_usNATIcmpId;	// NAT ICMP ID
};

// ICMP NAT table
class CIcmpNATTable
{
	// Hash table for TCP connections
	CIcmpNATEntry**		m_Table; // Used for allocating and searching NAT entries for outgoing packets
	CIcmpNATEntry**		m_PortTable; // Used for mapping incoming packets to NAT entries
public:
	CIcmpNATTable ();
	~CIcmpNATTable ();

	// Outgoing NAT methods
	CIcmpNATEntry* Allocate (in_addr ip_src, in_addr ip_dst, unsigned short icmp_id);
	CIcmpNATEntry* Find (in_addr ip_src, in_addr ip_dst, unsigned short icmp_id);

	// Incoming NAT methods
	CIcmpNATEntry* Map (unsigned short icmp_id);

	// Deleting entries methods
	void Free(CIcmpNATEntry* pNE);
	void RemoveAll();
};

// CsnatDlg dialog
class CsnatDlg : public CDialog
{
	OVERLAPPED	m_ovlp;
	HANDLE		m_hRoutingEvent_;
// Construction
public:
	CsnatDlg(CWnd* pParent = NULL);	// standard constructor
	~CsnatDlg();

// Dialog Data
	enum { IDD = IDD_SNAT_DIALOG };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support


// Implementation
protected:
	HICON m_hIcon;

	// Generated message map functions
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	CListCtrl	m_AdaptersList; // List control for network adapters
	CImageList* m_pImageList;	// Image list for m_AdaptersList
	CNdisApi	m_NdisApi;		// API object for communicating with WinpkFilter driver
private:
	int InitAdapterList(void);	// Initializes network interfaces list

	TCP_AdapterList m_AdList; // Adapters list structure filled by WinpkFilter driver
public:
	CNetworkInterfacesList		m_NetCardsList; // Network interfaces list
	CNetcardProp				m_NetcardProp;	// Netcard properties dialog
	unsigned int				m_dwAdapterCount; // Number of found adapters
	HANDLE						m_hNATThread;	// Packet processing thread handle
	HANDLE						m_hNATTerminateEvent; // This event is used for signalling packet processing thread termination
	CPortNATTable				m_TcpNatTable; // TCP NAT table
	CPortNATTable				m_UdpNatTable; // UDP NAT table
	CIcmpNATTable				m_IcmpNatTable; // ICMP NAT table
	in_addr						m_DNSIp; // DNS server IP address

	USHORT						m_ProviderMTU; // MTU of Provider interface
	USHORT						m_ClientMTU; //MTU of client interface
	
	BOOL						m_ForceRouting; //TRUE if Windows 7 or higher is used in case with WAN provider interface

	int InitializeAdapters(void);	// Initializes list of network adapters
	int	GetDNSIp(void);				// Uses IP helper API to obtain DNS IP address
	int UpdateDNSByIp(int nIp); //Uses registry search to obtain DNS corresponded with ip address of provider interface
	
	BOOL IsNeedToForceRouting(BYTE *MACAddress, DWORD dwDestIp, DWORD dwProviderIndex);

	void CheckMTUCorrelation(PINTERMEDIATE_BUFFER pBuffer, iphdr_ptr pIpHeader, tcphdr_ptr pTcpHeader);
	
	BOOL IsAddressExternal(int nDestIpAddress); 
	
	static unsigned __stdcall StartNAT ( void* pArguments ); // Main packet processing thread

	afx_msg void OnNMDblclkAdapters(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnBnClickedButtonstart();
public:
	afx_msg void OnClose();
};
