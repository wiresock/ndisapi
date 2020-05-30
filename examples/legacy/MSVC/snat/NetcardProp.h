/*************************************************************************/
/*				Copyright (c) 2000-2016 NT Kernel Resources.		     */
/*                           All Rights Reserved.                        */
/*                          http://www.ntkernel.com                      */
/*                           ndisrd@ntkernel.com                         */
/* Module Name:  NetcardProp.h			                                 */
/*                                                                       */
/* Abstract: CNetcardProp dialog declarations	      	                 */
/*                                                                       */
/*                                                                       */
/*************************************************************************/

#pragma once
#include "NetworkInterface.h"
#include "afxcmn.h"
#include "afxwin.h"

// CNetcardProp dialog

class CNetcardProp : public CDialog
{
	DECLARE_DYNAMIC(CNetcardProp)

public:
	CNetcardProp(CWnd* pParent = NULL);   // standard constructor
	virtual ~CNetcardProp();

// Dialog Data
	enum { IDD = IDD_INTERFACE_PROPERTIES };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
public:
	virtual BOOL OnInitDialog();
	
	CNetworkInterface*	m_pNetworkInterface; // points to associated CNetworkInterface structure
	CListCtrl			m_IpList; // control for the list of IP's
	CIPAddressCtrl		m_NATIp; // control for configuring NAT IP
	CComboBox			m_NATStatus; // control for setting NAT status for the interface
	CIPAddressCtrl		m_NatDNS;// control for setting NAT DNS ip address for the interface
	CButton				m_ClientDNS;// control for setting DNS spoofing status for the interface

	afx_msg void OnCbnSelchangeCombonat();
	afx_msg void OnNMDblclkListIp(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnIpnFieldchangedIpaddress1(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnBnClickedCheck1();
	
	
	afx_msg void OnBnClickedOk();
};
