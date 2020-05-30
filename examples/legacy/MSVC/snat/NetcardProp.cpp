/*************************************************************************/
/*				Copyright (c) 2000-2016 NT Kernel Resources.		     */
/*                           All Rights Reserved.                        */
/*                          http://www.ntkernel.com                      */
/*                           ndisrd@ntkernel.com                         */
/* Module Name:  NetcardProp.cpp		                                 */
/*                                                                       */
/* Abstract: CNetcardProp implementation file			                 */
/*                                                                       */
/*                                                                       */
/*************************************************************************/

#include "stdafx.h"
#include "snat.h"
#include "snatDlg.h"
#include "NetcardProp.h"
#include ".\netcardprop.h"


// CNetcardProp dialog

IMPLEMENT_DYNAMIC(CNetcardProp, CDialog)
CNetcardProp::CNetcardProp(CWnd* pParent /*=NULL*/)
	: CDialog(CNetcardProp::IDD, pParent)
	, m_pNetworkInterface(NULL)
{
}

CNetcardProp::~CNetcardProp()
{
}

void CNetcardProp::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST1, m_IpList);
	DDX_Control(pDX, IDC_IPADDRESSNAT, m_NATIp);
	DDX_Control(pDX, IDC_COMBONAT, m_NATStatus);
	DDX_Control(pDX, IDC_IPADDRESSDNS, m_NatDNS);
	DDX_Control(pDX, IDC_CHECK_DNS, m_ClientDNS);
}


BEGIN_MESSAGE_MAP(CNetcardProp, CDialog)
	ON_CBN_SELCHANGE(IDC_COMBONAT, OnCbnSelchangeCombonat)
	ON_NOTIFY(NM_DBLCLK, IDC_LISTIP, OnNMDblclkListIp)
	ON_BN_CLICKED(IDOK, &CNetcardProp::OnBnClickedOk)
END_MESSAGE_MAP()


// CNetcardProp message handlers

BOOL CNetcardProp::OnInitDialog()
{
	CDialog::OnInitDialog();

	// Set dialog caption
	CString zsCaption = m_pNetworkInterface->m_szUserFriendlyName + _T(" Properties");
	SetWindowText(zsCaption);

	
	// Set MAC address
	CString szMAC;
	szMAC.Format(
		"%.2X%.2X%.2X%.2X%.2X%.2X",
		m_pNetworkInterface->m_chMACAddr[0],
		m_pNetworkInterface->m_chMACAddr[1],
		m_pNetworkInterface->m_chMACAddr[2],
		m_pNetworkInterface->m_chMACAddr[3],
		m_pNetworkInterface->m_chMACAddr[4],
		m_pNetworkInterface->m_chMACAddr[5]
		);
	
	SetDlgItemText(IDC_MACADDR, szMAC);
	SetDlgItemText(IDC_INTNAME, m_pNetworkInterface->m_szInternalName);

	// Create columns for IP addresses list
	m_IpList.InsertColumn(0, _T("IP address"), LVCFMT_LEFT, 100);
	m_IpList.InsertColumn(1, _T("Network Mask"), LVCFMT_LEFT, 100);

	// Fill IP address list
	if(!m_pNetworkInterface->m_IpList.IsEmpty())
	{
		POSITION pos = m_pNetworkInterface->m_IpList.GetHeadPosition();

		for (int i=0; i < m_pNetworkInterface->m_IpList.GetCount(); ++i)
		{
			CIpAddr* pIp = m_pNetworkInterface->m_IpList.GetNext(pos);
			m_IpList.InsertItem ( i, pIp->m_szIp );
			m_IpList.SetItemText( i, 1, pIp->m_szMask );
		}
	}

	// Initialize NAT status control
	m_NATStatus.InsertString(0, _T("None"));
	m_NATStatus.InsertString(1, _T("Provider"));
	m_NATStatus.InsertString(2, _T("Client"));
	m_NATStatus.SetCurSel(m_pNetworkInterface->m_NATState);

	CWnd* pStatic = GetDlgItem(IDC_STATICIP);
	CWnd* pStaticDns = GetDlgItem(IDC_STATIC_DNS);

	if (m_pNetworkInterface->m_NATState == PROVIDER)
	{
		pStatic->ShowWindow(SW_SHOW);
		m_NATIp.ShowWindow(SW_SHOW);
		pStaticDns->ShowWindow(SW_SHOW);
		m_NatDNS.ShowWindow(SW_SHOW);
		m_ClientDNS.ShowWindow(SW_SHOW);

		m_NATIp.SetAddress(m_pNetworkInterface->m_NATIp.S_un.S_addr);
		m_NatDNS.SetAddress(ntohl(((CsnatDlg *)(theApp.m_pMainWnd))->m_DNSIp.S_un.S_addr));

		if(((CsnatDlg *)(theApp.m_pMainWnd))->m_DNSIp.S_un.S_addr == INADDR_ANY)
		{
			m_NatDNS.SetAddress(INADDR_LOOPBACK);
			m_ClientDNS.SetCheck(BST_CHECKED);
		}
	}

	return TRUE;  // return TRUE unless you set the focus to a control
	// EXCEPTION: OCX Property Pages should return FALSE
}

// Processes setting NAT interface status
void CNetcardProp::OnCbnSelchangeCombonat()
{
	CWnd* pStatic = GetDlgItem(IDC_STATICIP);
	CWnd* pStaticDns = GetDlgItem(IDC_STATIC_DNS);
	in_addr	  DNS;
	
	m_pNetworkInterface->m_NATState = (NAT_STATUS)m_NATStatus.GetCurSel();

	// If NAT state is set to PROVIDER -> show window for configuring NAT address
	if (m_pNetworkInterface->m_NATState == PROVIDER)
	{
		pStatic->ShowWindow(SW_SHOW);
		m_NATIp.ShowWindow(SW_SHOW);
		pStaticDns->ShowWindow(SW_SHOW);
		m_NatDNS.ShowWindow(SW_SHOW);
		m_ClientDNS.ShowWindow(SW_SHOW);
		
		CString szIp = m_IpList.GetItemText(0, 0);
		m_pNetworkInterface->m_NATIp.S_un.S_addr = htonl(inet_addr(szIp));
		m_NATIp.SetAddress(m_pNetworkInterface->m_NATIp.S_un.S_addr);

		DNS.S_un.S_addr = ntohl(((CsnatDlg *)(theApp.m_pMainWnd))->UpdateDNSByIp(inet_addr(szIp)));
		
		if((DNS.S_un.S_addr == INADDR_ANY) || (DNS.S_un.S_addr == INADDR_NONE))
		{
			DNS.S_un.S_addr = ntohl(((CsnatDlg *)(theApp.m_pMainWnd))->GetDNSIp());
		}

		if(DNS.S_un.S_addr == INADDR_LOOPBACK)
		{
			((CsnatDlg *)(theApp.m_pMainWnd))->m_DNSIp.S_un.S_addr = INADDR_ANY;
			m_ClientDNS.SetCheck(BST_CHECKED);
		}

		m_NatDNS.SetAddress(DNS.S_un.S_addr);
	}
	else
	{
		pStatic->ShowWindow(SW_HIDE);
		m_NATIp.ShowWindow(SW_HIDE);
		pStaticDns->ShowWindow(SW_HIDE);
		m_NatDNS.ShowWindow(SW_HIDE);
		m_ClientDNS.ShowWindow(SW_HIDE);

		m_NATIp.SetAddress(0);
	}
}

// Processes selection of IP address for the NAT
void CNetcardProp::OnNMDblclkListIp(NMHDR *pNMHDR, LRESULT *pResult)
{
	if (m_pNetworkInterface->m_NATState == PROVIDER)
	{
		int iIndex = m_IpList.GetSelectionMark();
		CString szIp = m_IpList.GetItemText(iIndex, 0);
		m_pNetworkInterface->m_NATIp.S_un.S_addr = htonl(inet_addr(szIp));
		m_NATIp.SetAddress(m_pNetworkInterface->m_NATIp.S_un.S_addr);
	}

	*pResult = 0;
}

void CNetcardProp::OnIpnFieldchangedIpaddress1(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMIPADDRESS pIPAddr = reinterpret_cast<LPNMIPADDRESS>(pNMHDR);
	// TODO: Add your control notification handler code here
	*pResult = 0;
}


void CNetcardProp::OnBnClickedOk()
{
	UpdateData(TRUE);

	if (m_pNetworkInterface->m_NATState == PROVIDER)
	{
		if(m_ClientDNS.GetCheck())
		{
			((CsnatDlg *)(theApp.m_pMainWnd))->m_DNSIp.S_un.S_addr = INADDR_ANY;
		}
		else
		{
			DWORD dwDNSIp = INADDR_ANY;

			m_NatDNS.GetAddress(dwDNSIp);

			((CsnatDlg *)(theApp.m_pMainWnd))->m_DNSIp.S_un.S_addr = ntohl(dwDNSIp);
		}
	}

	// TODO: Add your control notification handler code here
	OnOK();
}
