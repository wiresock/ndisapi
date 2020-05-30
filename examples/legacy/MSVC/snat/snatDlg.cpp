/*************************************************************************/
/*				Copyright (c) 2000-2016 NT Kernel Resources.		     */
/*                           All Rights Reserved.                        */
/*                          http://www.ntkernel.com                      */
/*                           ndisrd@ntkernel.com                         */
/* Module Name:  snatDlg.cpp			                                 */
/*                                                                       */
/* Abstract: Main file for the SNAT projects (defines CsnatDlg class)    */
/*                                                                       */
/*                                                                       */
/*************************************************************************/

#include "stdafx.h"
#include "process.h"
#include "snat.h"
#include "snatDlg.h"
#include "iphlp.h"
#include ".\snatdlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

CNATEntry::CNATEntry ():
nextEntry(NULL),
prevEntry(NULL)
{}

CPortNATEntry::CPortNATEntry():
CNATEntry()
{}

CIcmpNATEntry::CIcmpNATEntry():
CNATEntry()
{}

CPortNATTable::CPortNATTable ()
{
	// Allocate NAT port tables
	m_PortTable = (CPortNATEntry**)::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(DWORD_PTR)*NAT_TABLE_SIZE);
	m_Table = (CPortNATEntry**)::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(DWORD_PTR)*NAT_TABLE_SIZE);
}

CPortNATTable::~CPortNATTable ()
{
	// Free NAT port tables
	::HeapFree(::GetProcessHeap(), 0, m_PortTable);
	::HeapFree(::GetProcessHeap(), 0, m_Table);
}

// Allocates and initializes new NAT entry
CPortNATEntry* CPortNATTable::Allocate(in_addr ip_src, unsigned short port_src, in_addr ip_dst, unsigned short port_dst)
{
	SYSTEMTIME		systime;
	FILETIME		ftime;
	ULARGE_INTEGER	time;

	//Get current time
	::GetSystemTime(&systime);
	::SystemTimeToFileTime(&systime, &ftime);
	time.HighPart = ftime.dwHighDateTime;
	time.LowPart = ftime.dwLowDateTime;

	// Find first non-allocated or outdated local port
	for (int i = 10000; i < NAT_TABLE_SIZE; ++i)
	{
		if (m_PortTable[i] != NULL)
		{
			// Free port if NAT entry is out-of-date
			if(((time.QuadPart - m_PortTable[i]->m_ulTimeStamp.QuadPart)/10000000) > NAT_TIMEOUT)
			{
				Free(m_PortTable[i]);
			}
		}

		if (m_PortTable[i] == NULL)
		{
			// Found free port, allocate and initialize new NAT entry
			CPortNATEntry* pNE = new CPortNATEntry;
			pNE->m_IpSrc.S_un.S_addr = ntohl(ip_src.S_un.S_addr);
			pNE->m_IpDst.S_un.S_addr = ntohl(ip_dst.S_un.S_addr);
			pNE->m_usDstPort = ntohs(port_dst);
            pNE->m_usNATPort = i;
			pNE->m_usSrcPort = ntohs (port_src);
			pNE->m_ulTimeStamp = time;

			m_PortTable[i] = pNE;

			unsigned short usIndex = pNE->m_IpDst.S_un.S_un_w.s_w1 + pNE->m_IpDst.S_un.S_un_w.s_w2;

			pNE->nextEntry = m_Table[usIndex];
			if(m_Table[usIndex])
				m_Table[usIndex]->prevEntry = pNE;
			m_Table[usIndex] = pNE;

			return pNE;
		}
	}

	return NULL;
}

// Releases all resources associated with NAT entry and removes it from the NAT table
void CPortNATTable::Free(CPortNATEntry* pNE)
{
	// Deallocate entry resources
	unsigned short usDel = pNE->m_IpDst.S_un.S_un_w.s_w1 + pNE->m_IpDst.S_un.S_un_w.s_w2;

	if (pNE->prevEntry == NULL)
	{
		// Head of the list
		m_Table[usDel] = (CPortNATEntry*)pNE->nextEntry;
		if (m_Table[usDel])
			m_Table[usDel]->prevEntry = NULL;
	}
	else
	{
		// In the middle or at the end of the list
		pNE->prevEntry->nextEntry = pNE->nextEntry;
		if (pNE->nextEntry)
			pNE->nextEntry->prevEntry = pNE->prevEntry;
	}
				
	
	m_PortTable[pNE->m_usNATPort] = NULL;
	delete pNE;
}

// Removes all entries form the NAT table
void CPortNATTable::RemoveAll()
{
	for (int i = 0; i < NAT_TABLE_SIZE; ++i)
	{
		if (m_PortTable[i] != NULL)
		{
			Free(m_PortTable[i]);
		}
	}
}

// Finds the corresponding NAT entry in the table if it exists
CPortNATEntry* CPortNATTable::Find (in_addr ip_src, unsigned short port_src, in_addr ip_dst, unsigned short port_dst)
{
	unsigned short usIndex = ntohs(ip_dst.S_un.S_un_w.s_w1) + ntohs(ip_dst.S_un.S_un_w.s_w2);
	
	CPortNATEntry* pNE = m_Table[usIndex];

	while (pNE)
	{
		if ((pNE->m_IpSrc.S_un.S_addr == ntohl(ip_src.S_un.S_addr))&&
			(pNE->m_IpDst.S_un.S_addr == ntohl(ip_dst.S_un.S_addr))&&
			(pNE->m_usDstPort == ntohs(port_dst))&&
			(pNE->m_usSrcPort == ntohs(port_src))
			)
		{
			SYSTEMTIME systime;
			FILETIME ftime;

			// Update timestamp
			::GetSystemTime(&systime);
			::SystemTimeToFileTime(&systime, &ftime);
			pNE->m_ulTimeStamp.HighPart = ftime.dwHighDateTime;
			pNE->m_ulTimeStamp.LowPart = ftime.dwLowDateTime;

			return pNE;
		}

		pNE = (CPortNATEntry*)pNE->nextEntry;
	}

	return pNE;
}

// Maps local port to the corresponding NAT entry
CPortNATEntry* CPortNATTable::Map (unsigned short port_dst)
{
	return m_PortTable[ntohs(port_dst)];
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

CIcmpNATTable::CIcmpNATTable ()
{
	// Allocate NAT port tables
	m_PortTable = (CIcmpNATEntry**)::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(DWORD_PTR)*NAT_TABLE_SIZE);
	m_Table = (CIcmpNATEntry**)::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(DWORD_PTR)*NAT_TABLE_SIZE);
}

CIcmpNATTable::~CIcmpNATTable ()
{
	// Free NAT port tables
	::HeapFree(::GetProcessHeap(), 0, m_PortTable);
	::HeapFree(::GetProcessHeap(), 0, m_Table);
}

// Allocates and initializes new NAT entry
CIcmpNATEntry* CIcmpNATTable::Allocate(in_addr ip_src, in_addr ip_dst, unsigned short icmp_id)
{
	SYSTEMTIME		systime;
	FILETIME		ftime;
	ULARGE_INTEGER	time;

	//Get current time
	::GetSystemTime(&systime);
	::SystemTimeToFileTime(&systime, &ftime);
	time.HighPart = ftime.dwHighDateTime;
	time.LowPart = ftime.dwLowDateTime;

	// Find first non-allocated or outdated local ID
	for (int i = 2; i < NAT_TABLE_SIZE; ++i)
	{
		if (m_PortTable[i] != NULL)
		{
			// Free ID if NAT entry is out-of-date
			if(((time.QuadPart - m_PortTable[i]->m_ulTimeStamp.QuadPart)/10000000) > NAT_TIMEOUT)
			{
				Free(m_PortTable[i]);
			}
		}

		if (m_PortTable[i] == NULL)
		{
			// Found free port, allocate and initialize new NAT entry
			CIcmpNATEntry* pNE = new CIcmpNATEntry;
			pNE->m_IpSrc.S_un.S_addr = ntohl(ip_src.S_un.S_addr);
			pNE->m_IpDst.S_un.S_addr = ntohl(ip_dst.S_un.S_addr);
			pNE->m_usIcmpId = ntohs(icmp_id);
            pNE->m_usNATIcmpId = i;
			pNE->m_ulTimeStamp = time;

			m_PortTable[i] = pNE;

			unsigned short usIndex = pNE->m_IpDst.S_un.S_un_w.s_w1 + pNE->m_IpDst.S_un.S_un_w.s_w2;

			pNE->nextEntry = m_Table[usIndex];
			if(m_Table[usIndex])
				m_Table[usIndex]->prevEntry = pNE;
			m_Table[usIndex] = pNE;

			return pNE;
		}
	}

	return NULL;
}

// Releases all resources associated with NAT entry and removes it from the NAT table
void CIcmpNATTable::Free(CIcmpNATEntry* pNE)
{
	// Deallocate entry resources
	unsigned short usDel = pNE->m_IpDst.S_un.S_un_w.s_w1 + pNE->m_IpDst.S_un.S_un_w.s_w2;

	if (pNE->prevEntry == NULL)
	{
		// Head of the list
		m_Table[usDel] = (CIcmpNATEntry*)pNE->nextEntry;
		if (m_Table[usDel])
			m_Table[usDel]->prevEntry = NULL;
	}
	else
	{
		// In the middle or at the end of the list
		pNE->prevEntry->nextEntry = pNE->nextEntry;
		if (pNE->nextEntry)
			pNE->nextEntry->prevEntry = pNE->prevEntry;
	}
				
	
	m_PortTable[pNE->m_usNATIcmpId] = NULL;
	delete pNE;
}

// Removes all entries form the NAT table
void CIcmpNATTable::RemoveAll()
{
	for (int i = 0; i < NAT_TABLE_SIZE; ++i)
	{
		if (m_PortTable[i] != NULL)
		{
			Free(m_PortTable[i]);
		}
	}
}

// Finds the corresponding NAT entry in the table if it exists
CIcmpNATEntry* CIcmpNATTable::Find (in_addr ip_src, in_addr ip_dst, unsigned short icmp_id)
{
	unsigned short usIndex = ntohs(ip_dst.S_un.S_un_w.s_w1) + ntohs(ip_dst.S_un.S_un_w.s_w2);
	
	CIcmpNATEntry* pNE = m_Table[usIndex];

	while (pNE)
	{
		if ((pNE->m_IpSrc.S_un.S_addr == ntohl(ip_src.S_un.S_addr))&&
			(pNE->m_IpDst.S_un.S_addr == ntohl(ip_dst.S_un.S_addr))&&
			(pNE->m_usIcmpId == ntohs(icmp_id))
			)
		{
			SYSTEMTIME systime;
			FILETIME ftime;

			// Update timestamp
			::GetSystemTime(&systime);
			::SystemTimeToFileTime(&systime, &ftime);
			pNE->m_ulTimeStamp.HighPart = ftime.dwHighDateTime;
			pNE->m_ulTimeStamp.LowPart = ftime.dwLowDateTime;

			return pNE;
		}

		pNE = (CIcmpNATEntry*)pNE->nextEntry;
	}

	return pNE;
}

// Maps local port to the corresponding NAT entry
CIcmpNATEntry* CIcmpNATTable::Map (unsigned short icmp_id)
{
	return m_PortTable[ntohs(icmp_id)];
}

// CAboutDlg dialog used for App About

class CAboutDlg : public CDialog
{
public:
	CAboutDlg();

// Dialog Data
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

// Implementation
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialog(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialog)
END_MESSAGE_MAP()


// CsnatDlg dialog



CsnatDlg::CsnatDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CsnatDlg::IDD, pParent)
	, m_pImageList(NULL)
	, m_dwAdapterCount(0)
    , m_hRoutingEvent_(::CreateEvent(nullptr, TRUE, FALSE, nullptr))
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

CsnatDlg::~CsnatDlg()
{
	CNetworkInterface* pNI = NULL;

	if (!m_NetCardsList.IsEmpty())
	{
		POSITION pos = m_NetCardsList.GetHeadPosition();
		
		for (unsigned i = 0; i < m_dwAdapterCount; ++i)
		{
			pNI = m_NetCardsList.GetNext(pos);

			delete pNI;

		}
	}

	if(m_hRoutingEvent_ != nullptr)
		::CloseHandle(m_hRoutingEvent_);

	delete m_pImageList;
}

void CsnatDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_ADAPTERS, m_AdaptersList);
}

BEGIN_MESSAGE_MAP(CsnatDlg, CDialog)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	//}}AFX_MSG_MAP
	ON_NOTIFY(NM_DBLCLK, IDC_ADAPTERS, OnNMDblclkAdapters)
	ON_BN_CLICKED(IDC_BUTTONSTART, OnBnClickedButtonstart)
	ON_WM_CLOSE()
END_MESSAGE_MAP()


// CsnatDlg message handlers

BOOL CsnatDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// Add "About..." menu item to system menu.

	// IDM_ABOUTBOX must be in the system command range.
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		CString strAboutMenu;
		strAboutMenu.LoadString(IDS_ABOUTBOX);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	// Set dialog caption
	SetWindowText("Internet Gateway");

	// Initalize network interfaces and corresponding control
	InitAdapterList();
	
	return TRUE;  // return TRUE  unless you set the focus to a control
}

void CsnatDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialog::OnSysCommand(nID, lParam);
	}
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CsnatDlg::OnPaint() 
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

// The system calls this function to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CsnatDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

//Initializes network interfaces list
int CsnatDlg::InitAdapterList(void)
{
	CNetworkInterface*	pNI;
	CString				szMACAddr;

	// Initialize image list
	m_pImageList = new CImageList;
	ASSERT(m_pImageList != NULL);
	m_pImageList->Create(16, 16, ILC_COLOR8|ILC_MASK, 2, 2);
	m_pImageList->Add(theApp.LoadIcon(IDI_MODEM));
	m_pImageList->Add(theApp.LoadIcon(IDI_NETCARD));
	m_AdaptersList.SetImageList(m_pImageList, LVSIL_SMALL);

	// Create columns
	m_AdaptersList.InsertColumn(0, _T("Connection name"), LVCFMT_LEFT, 180);
	m_AdaptersList.InsertColumn(1, _T("MAC address"), LVCFMT_LEFT, 100);
	m_AdaptersList.InsertColumn (2, _T("NAT Status"), LVCFMT_LEFT, 100);

	// Set up network adapters list control
	if(InitializeAdapters())
	{
		if (!m_NetCardsList.IsEmpty())
		{
			POSITION pos = m_NetCardsList.GetHeadPosition();
			for (unsigned i = 0; i < m_dwAdapterCount; ++i)
			{
				pNI = m_NetCardsList.GetNext(pos);

				int iIndex = m_AdaptersList.InsertItem(i, pNI->m_szUserFriendlyName, pNI->m_bIsWan?0:1);
				
				m_AdaptersList.SetItemData(iIndex, (DWORD_PTR)pNI);

				szMACAddr.Format(
					"%.2X%.2X%.2X%.2X%.2X%.2X",
					pNI->m_chMACAddr[0],
					pNI->m_chMACAddr[1],
					pNI->m_chMACAddr[2],
					pNI->m_chMACAddr[3],
					pNI->m_chMACAddr[4],
					pNI->m_chMACAddr[5]
					);

				m_AdaptersList.SetItemText(iIndex, 1, szMACAddr);

				CString szState;
				switch(pNI->m_NATState)
				{
				case NONE:
					szState = _T("None");
					break;
				case PROVIDER:
					szState = _T("Provider");
					break;
				case CLIENT:
					szState = _T("Client");
					break;
				default:
					break;
				}

				m_AdaptersList.SetItemText(iIndex, 2, szState);
			}
		}
	}
	else
	{
		::MessageBox(
			NULL,
			_T("WinpkFilter driver is not loaded. Please install WinpkFilter run time libraries"),
			_T("WinpkFilter driver not found"),
			MB_OK|MB_ICONEXCLAMATION
			);
	}

	return 0;
}

int CsnatDlg::InitializeAdapters(void)
{
	OSVERSIONINFO	verInfo;
	char			szFriendlyName[MAX_PATH*4];

	verInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	GetVersionEx ( &verInfo );

	if(m_NdisApi.IsDriverLoaded())
	{
		m_NdisApi.GetTcpipBoundAdaptersInfo ( &m_AdList );
		m_dwAdapterCount = m_AdList.m_nAdapterCount;

		for (unsigned i = 0; i < m_dwAdapterCount; ++i)
		{
			// Build the list of network inetrface instances
			CNetworkInterface* pNI = new CNetworkInterface;
			pNI->m_szInternalName = (LPSTR)m_AdList.m_szAdapterNameList[i];

			if (verInfo.dwPlatformId == VER_PLATFORM_WIN32_NT)
			{
				if (verInfo.dwMajorVersion >= 5)
				{
					// Windows 2000 or XP
					CNdisApi::ConvertWindows2000AdapterName((const char*)m_AdList.m_szAdapterNameList[i], szFriendlyName, MAX_PATH*4);
				}
				else if (verInfo.dwMajorVersion == 4)
				{
					// Windows NT 4.0	
					CNdisApi::ConvertWindowsNTAdapterName((const char*)m_AdList.m_szAdapterNameList[i], szFriendlyName, MAX_PATH*4);
				}
			}
			else
			{
				// Windows 9x/ME
				CNdisApi::ConvertWindows9xAdapterName((const char*)m_AdList.m_szAdapterNameList[i], szFriendlyName, MAX_PATH*4);
			}

			pNI->m_szUserFriendlyName = szFriendlyName;
			memcpy (pNI->m_chMACAddr, m_AdList.m_czCurrentAddress[i], ETHER_ADDR_LENGTH);
			pNI->m_hAdapter = m_AdList.m_nAdapterHandle[i];
			(m_AdList.m_nAdapterMediumList[i])?pNI->m_bIsWan = true:pNI->m_bIsWan = false;

			pNI->InitIPInformation();
			
			pNI->InitMTUInformation();

			m_NetCardsList.AddTail (pNI);
		}

		return 1;
	}
	else
		return 0;
}

// Opens network connection properties window and processes the results
void CsnatDlg::OnNMDblclkAdapters(NMHDR *pNMHDR, LRESULT *pResult)
{
	int iCurrentSel = m_AdaptersList.GetSelectionMark();

	if (iCurrentSel == -1)
		return;

	CNetworkInterface* pNI = (CNetworkInterface*)m_AdaptersList.GetItemData(iCurrentSel);

	m_NetcardProp.m_pNetworkInterface = pNI;

	if (IDOK == m_NetcardProp.DoModal())
	{
		CString szState;
		switch(pNI->m_NATState)
		{
			case NONE:
				szState = _T("None");
				break;
			case PROVIDER:
				szState = _T("Provider");
				break;
			case CLIENT:
				szState = _T("Client");
				break;
			default:
				break;
		}

		m_AdaptersList.SetItemText(iCurrentSel, 2, szState);

		// if PROVIDER set then reset all other providers if have any
		if (pNI->m_NATState == PROVIDER)
		{
			CNetworkInterface* pNIterator; 
			POSITION pos = m_NetCardsList.GetHeadPosition();
			for (unsigned i = 0; i < m_dwAdapterCount; ++i)
			{
				pNIterator = m_NetCardsList.GetNext(pos);

				if((pNIterator != pNI)&&(pNIterator->m_NATState == PROVIDER))
				{
					LVFINDINFO info;
					int nIndex;

					info.flags = LVFI_STRING;
					info.psz = pNIterator->m_szUserFriendlyName;

					nIndex = m_AdaptersList.FindItem(&info);

					m_AdaptersList.SetItemText(nIndex, 2, _T("None"));

					pNIterator->m_NATState = NONE;
				}
			}

		}

		// If we have at least one PROVIDER and one CLIENT we must allow user to start NAT thread
		CNetworkInterface* pNIterator; 
		BOOL bIsProvider = false;
		BOOL bIsClient = false;
		POSITION pos = m_NetCardsList.GetHeadPosition();
		for (unsigned i = 0; i < m_dwAdapterCount; ++i)
		{
			pNIterator = m_NetCardsList.GetNext(pos);

			if (pNIterator->m_NATState == PROVIDER)
				bIsProvider = true;

			if (pNIterator->m_NATState == CLIENT)
				bIsClient = true;
		}

		CWnd* pStartButton = GetDlgItem(IDC_BUTTONSTART);

		if (bIsProvider && bIsClient)
			pStartButton->EnableWindow();
		else
			pStartButton->EnableWindow(false);
	}
	
	*pResult = 0;
}

// User wants to start or stop NAT thread, perform necessary operations
void CsnatDlg::OnBnClickedButtonstart()
{
	CWnd*		pStartButton = GetDlgItem(IDC_BUTTONSTART);
	CWnd*		pList = GetDlgItem(IDC_ADAPTERS);
	CString		szCaption;
	unsigned	dwID;

	pStartButton->GetWindowText(szCaption);

	// Simply check the button caption text
	if (szCaption == _T("Start NAT"))
	{
		// User wants to start NAT

		HANDLE routing_handle = INVALID_HANDLE_VALUE;
		m_ovlp.hEvent = m_hRoutingEvent_;

		// Attempt to enable IP routing (on Windows 10 requires Administrator)
		if ((ERROR_IO_PENDING != ::EnableRouter(&routing_handle, &m_ovlp)))
		{
			::MessageBox(
			NULL,
			_T("Failed to enable IP routing! Please start application as Administrator."),
			_T("Failed to enable IP routing"),
			MB_OK|MB_ICONEXCLAMATION
			);

			return;
		}
		
		// Change button caption
		pStartButton->SetWindowText(_T("Stop NAT"));

		// Disable network adapters list control
		pList->EnableWindow(false);

		// Create thread terminate event
		m_hNATTerminateEvent = ::CreateEvent(NULL, TRUE, FALSE, NULL);

		// Start NAT processing thread
		m_hNATThread = (HANDLE)_beginthreadex ( 
								NULL,
								0,
								CsnatDlg::StartNAT,
								this,
								0,
								&dwID
								);

	}
	else
	{
		// User wants to stop NAT thread, 
		// signal thread to stop and wait until it exits
		if (m_hNATThread)
		{
			::SetEvent(m_hNATTerminateEvent);
			::WaitForSingleObject(m_hNATThread, INFINITE);
			m_hNATThread = NULL;
		}
		// Change button caption
		pStartButton->SetWindowText(_T("Start NAT"));
		// Enable network adapters list control
		pList->EnableWindow();

		::UnenableRouter(&m_ovlp, nullptr);
	}
}

void CsnatDlg::CheckMTUCorrelation(PINTERMEDIATE_BUFFER pBuffer, iphdr_ptr pIpHeader, tcphdr_ptr pTcpHeader)
{
	//Check if provider MTU is bigger than client MTU everything is OK.
	if(m_ProviderMTU >= m_ClientMTU)
		return;

	mss_tcp_options_ptr	pTcpOptions;

	if(pTcpHeader->th_off == TCP_NO_OPTIONS)//No tcp options is on header
	{
		//Set mss corresponded with provider MTU
	
		pTcpOptions = (mss_tcp_options_ptr)((PUCHAR)pTcpHeader + sizeof(tcphdr));

		pTcpOptions->mss_type = MSS_TYPE;
		pTcpOptions->mss_option_length = sizeof(DWORD);
		pTcpOptions->mss_value = ntohs(m_ProviderMTU - sizeof(iphdr) - sizeof(tcphdr));
	
		pTcpHeader->th_off += sizeof(mss_tcp_options)/sizeof(DWORD);

		pIpHeader->ip_len = ntohs(ntohs(pIpHeader->ip_len) + sizeof(mss_tcp_options));

		pBuffer->m_Length+= sizeof(mss_tcp_options);
	}
	else
	{
		//Find existed MSS TCP option in header
		PUCHAR	pOption = (PUCHAR)((PUCHAR)pTcpHeader + sizeof(tcphdr));
		
		while(TRUE)
		{
			if(*pOption == MSS_TYPE)
			{
				pTcpOptions = (mss_tcp_options_ptr)pOption;

				pTcpOptions->mss_value = ntohs(m_ProviderMTU - sizeof(iphdr) - sizeof(tcphdr));

				return;
			}
			else
			{
				if(*pOption == 0)//End of options list
				{
					break;
				}
				
				if(*pOption == 1)//No operation (NOP, Padding) 
				{
					pOption += 1;
				}
				else
				{
					pOption += *(pOption + 1);
				}
			}

			if((unsigned)(pOption - ((PUCHAR)pTcpHeader + sizeof(tcphdr))) >= (pTcpHeader->th_off - TCP_NO_OPTIONS)*sizeof(DWORD))
				break;
		}

		//MSS options is not found in tcp options
		pOption = (PUCHAR)((PUCHAR)pTcpHeader + sizeof(tcphdr));

		memcpy(pOption + sizeof(mss_tcp_options), pOption, (pTcpHeader->th_off - TCP_NO_OPTIONS) *sizeof(DWORD));
		
		pTcpOptions = (mss_tcp_options_ptr)pOption;

		pTcpOptions->mss_type = MSS_TYPE;
		pTcpOptions->mss_option_length = sizeof(DWORD);
		pTcpOptions->mss_value = ntohs(m_ProviderMTU - sizeof(iphdr) - sizeof(tcphdr));

		pTcpHeader->th_off += sizeof(mss_tcp_options)/sizeof(DWORD);

		pIpHeader->ip_len = ntohs(ntohs(pIpHeader->ip_len) + sizeof(mss_tcp_options));

		pBuffer->m_Length+= sizeof(mss_tcp_options);
	}
};
//
// Main working Thread which implements the dynamic NAT
//
unsigned __stdcall CsnatDlg::StartNAT ( void* pArguments )
{
	CsnatDlg*			pDlg = (CsnatDlg*)pArguments;
	HANDLE				hEvents[ADAPTER_LIST_SIZE + 1];
	CNetworkInterface*	hAdapters [ADAPTER_LIST_SIZE + 1];
	CNetworkInterface	*pNetCard, *pProviderCard;
	unsigned			dwActiveAdaptersCount = 1;
	ADAPTER_MODE		Mode;
	ETH_REQUEST			Request;
	INTERMEDIATE_BUFFER PacketBuffer;
	DWORD				dwWait, dwIndex;
	ether_header*		pEthHeader;
	iphdr*				pIpHeader;
	tcphdr*				pTcpHeader;
	udphdr*				pUdpHeader;
	icmphdr*			pIcmpHeader;

	BOOL				bInit = FALSE;
	BYTE				MACClient[ETHER_ADDR_LENGTH];
	BYTE				MACServer[ETHER_ADDR_LENGTH];
	
	BOOL				bForceRouting	= FALSE;
	BOOL				bNeedToBeRouted = FALSE;

	static int			dns = 0;

	Mode.dwFlags = MSTCP_FLAG_SENT_TUNNEL|MSTCP_FLAG_RECV_TUNNEL|MSTCP_FLAG_LOOPBACK_BLOCK|MSTCP_FLAG_LOOPBACK_FILTER;

	hEvents[0] = pDlg->m_hNATTerminateEvent;

	// Walk adapters list and initialize provider and clients interfaces
	POSITION pos = pDlg->m_NetCardsList.GetHeadPosition();

	for (unsigned i = 0; i < pDlg->m_dwAdapterCount; ++i)
	{
		pNetCard = (CNetworkInterface*)pDlg->m_NetCardsList.GetNext(pos);

		if ((pNetCard->m_NATState == CLIENT) || (pNetCard->m_NATState == PROVIDER))
		{
			hAdapters[dwActiveAdaptersCount] = pNetCard;
			hEvents[dwActiveAdaptersCount] = ::CreateEvent(NULL, TRUE, FALSE, NULL);
			pDlg->m_NdisApi.SetPacketEvent(pNetCard->m_hAdapter, hEvents[dwActiveAdaptersCount]);
			Mode.hAdapterHandle = pNetCard->m_hAdapter;
			pDlg->m_NdisApi.SetAdapterMode(&Mode);
			dwActiveAdaptersCount++;

			if(pNetCard->m_NATState == PROVIDER)
			{
				pProviderCard = pNetCard;

				pProviderCard = pNetCard;

				pDlg->m_ProviderMTU = pNetCard->m_MTU;

				if(CVersionInfo().IsWindows7OrGreater())
				{
					if(IsNdiswanIp(pNetCard->m_szInternalName.GetString()))
					{
						RAS_LINKS RasLinks;

						pDlg->m_NdisApi.GetRasLinks(pNetCard->m_hAdapter, &RasLinks);
						
						for ( unsigned k = 0; k < RasLinks.nNumberOfLinks; ++k )
						{
							DWORD dwWanIp = *((PDWORD)&(RasLinks.RasLinks[k].ProtocolBuffer[584]));
							
							if(ntohl(dwWanIp) == pNetCard->m_NATIp.S_un.S_addr)
							{
								memcpy(MACClient, RasLinks.RasLinks[k].LocalAddress, ETH_ALEN);
								memcpy(MACServer, RasLinks.RasLinks[k].RemoteAddress, ETH_ALEN);

								bForceRouting = TRUE;

								break;
							}
						}
						
					}
				}
			}
			else
			{
				pDlg->m_ClientMTU = pNetCard->m_MTU;
			}
		}
	}

	// Initialize Request
	ZeroMemory ( &Request, sizeof(ETH_REQUEST) );
	ZeroMemory ( &PacketBuffer, sizeof(INTERMEDIATE_BUFFER) );
	Request.EthPacket.Buffer = &PacketBuffer;

	static int Num = 0;

	do
	{
		dwWait = ::WaitForMultipleObjects(
			dwActiveAdaptersCount,
			hEvents,
			FALSE,
			INFINITE
			);

		dwIndex = dwWait - WAIT_OBJECT_0;

		if (!dwIndex)
			continue;

		Request.hAdapterHandle = hAdapters[dwIndex]->m_hAdapter;

		// Read all queued packets from the specified interface
		while(pDlg->m_NdisApi.ReadPacket(&Request))
		{
			pEthHeader = (ether_header*)PacketBuffer.m_IBuffer;
			
			if ( ntohs(pEthHeader->h_proto) == ETH_P_IP )
			{
				pIpHeader = (iphdr*)(PacketBuffer.m_IBuffer + ETHER_HEADER_LENGTH);

				// Check if connection is established from local system (we don't do NAT processing
				// for local system)
				
				BOOL bIsLocalAddress = hAdapters[dwIndex]->IsLocalAddress(&pIpHeader->ip_src);

				if (bIsLocalAddress && (PacketBuffer.m_dwDeviceFlags == PACKET_FLAG_ON_SEND))
				{
					// Place packet on the network interface
					pDlg->m_NdisApi.SendPacketToAdapter(&Request);
					
					continue;
				}

				
				if((bForceRouting) &&(hAdapters[dwIndex]->m_NATState == CLIENT) && (PacketBuffer.m_dwDeviceFlags == PACKET_FLAG_ON_RECEIVE))
				{
					bNeedToBeRouted = pDlg->IsNeedToForceRouting(pEthHeader->h_dest, pIpHeader->ip_dst.S_un.S_addr, pProviderCard->m_Index);
				}

				// TCP packet processing
				if (pIpHeader->ip_p == IPPROTO_TCP)
				{
					// This is TCP packet, get TCP header pointer
					pTcpHeader = (tcphdr*)(((PUCHAR)pIpHeader) + sizeof(DWORD)*pIpHeader->ip_hl);

					// Outgoing TCP packets processing
					if(((bForceRouting) && (bNeedToBeRouted) &&(hAdapters[dwIndex]->m_NATState == CLIENT)&&(PacketBuffer.m_dwDeviceFlags == PACKET_FLAG_ON_RECEIVE))
						||
						((!bForceRouting) &&(hAdapters[dwIndex]->m_NATState == PROVIDER)&&(PacketBuffer.m_dwDeviceFlags == PACKET_FLAG_ON_SEND)))
					{
						CPortNATEntry* pTcpNE = NULL;
						
						if (pTcpHeader->th_flags == TH_SYN)
						{
							// New TCP connnection established, allocate dynamic NAT entry
							pTcpNE = pDlg->m_TcpNatTable.Allocate(pIpHeader->ip_src, pTcpHeader->th_sport, pIpHeader->ip_dst, pTcpHeader->th_dport);
							
							if(pTcpNE)
							{
								pTcpNE->m_IpNAT = bForceRouting?pProviderCard->m_NATIp:hAdapters[dwIndex]->m_NATIp;
							}

							pDlg->CheckMTUCorrelation(&PacketBuffer, pIpHeader, pTcpHeader);
						}
						else
						{
							// Try to locate existing NAT entry
							pTcpNE = pDlg->m_TcpNatTable.Find(pIpHeader->ip_src, pTcpHeader->th_sport, pIpHeader->ip_dst, pTcpHeader->th_dport);
						}

						if (pTcpNE)
						{
							// If NAT entry is found perform NAT processing
							pIpHeader->ip_src.S_un.S_addr = htonl(pTcpNE->m_IpNAT.S_un.S_addr);
							pTcpHeader->th_sport = htons(pTcpNE->m_usNATPort);
							// Recalculate checksums
							RecalculateTCPChecksum (&PacketBuffer);
							RecalculateIPChecksum (&PacketBuffer);

							if (bForceRouting)
							{
								memcpy(pEthHeader->h_dest, MACServer, ETHER_ADDR_LENGTH);
								memcpy(pEthHeader->h_source, MACClient, ETHER_ADDR_LENGTH);

								PacketBuffer.m_dwDeviceFlags = PACKET_FLAG_ON_SEND;

								Request.hAdapterHandle = pProviderCard->m_hAdapter;
								
								goto finish;
							}
						}
					}
					
					// Incoming TCP packets processing
					if ((hAdapters[dwIndex]->m_NATState == PROVIDER)&&
					   (PacketBuffer.m_dwDeviceFlags == PACKET_FLAG_ON_RECEIVE))
					{
						// Map connection to the NAT entry if the one exists
						CPortNATEntry* pTcpNE = pDlg->m_TcpNatTable.Map(pTcpHeader->th_dport);
						if (pTcpNE)
						{
							// NAT entry exists, make NAT processing
							if (htonl(pTcpNE->m_IpDst.S_un.S_addr) == pIpHeader->ip_src.S_un.S_addr)
							{
								pIpHeader->ip_dst.S_un.S_addr = htonl(pTcpNE->m_IpSrc.S_un.S_addr);
								pTcpHeader->th_dport = htons(pTcpNE->m_usSrcPort);
								RecalculateTCPChecksum (&PacketBuffer);
								RecalculateIPChecksum (&PacketBuffer);
							}
						}
					}

								
				}
				// UDP packets processing
				if (pIpHeader->ip_p == IPPROTO_UDP)
				{
					// This is UDP packet, get UDP header pointer
					pUdpHeader = (udphdr*)(((PUCHAR)pIpHeader) + sizeof(DWORD)*pIpHeader->ip_hl);

					
					 //DNS hook
					 //If we receive DNS packet on the NAT client adapter then we redirect it 
					 //to this system configured DNS server
					if((pDlg->m_DNSIp.S_un.S_addr != INADDR_ANY) && (pDlg->m_DNSIp.S_un.S_addr != INADDR_NONE))
					{
						if ((hAdapters[dwIndex]->m_NATState == CLIENT)&&
					   (PacketBuffer.m_dwDeviceFlags == PACKET_FLAG_ON_RECEIVE))
						{
							if (ntohs(pUdpHeader->th_dport) == 53/*DNS port*/)
							{
								// Save the DNS IP used by the NAT client system
								hAdapters[dwIndex]->m_LocalDNS.S_un.S_addr = ntohl(pIpHeader->ip_dst.S_un.S_addr);
								
								pIpHeader->ip_dst.S_un.S_addr = pDlg->m_DNSIp.S_un.S_addr;
							
								if(bForceRouting) 
								{
									bNeedToBeRouted = pDlg->IsNeedToForceRouting(pEthHeader->h_dest, pIpHeader->ip_dst.S_un.S_addr, pProviderCard->m_Index);
								}

								RecalculateUDPChecksum(&PacketBuffer);
								RecalculateIPChecksum (&PacketBuffer);
							}
						}

					
						// DNS reply came, substitute source IP back to the original DNS address
						if ((hAdapters[dwIndex]->m_NATState == CLIENT)&&
						   (PacketBuffer.m_dwDeviceFlags == PACKET_FLAG_ON_SEND))
						{
							if (ntohs(pUdpHeader->th_sport) == 53/*DNS port*/)
							{
								pIpHeader->ip_src.S_un.S_addr = htonl(hAdapters[dwIndex]->m_LocalDNS.S_un.S_addr);
								RecalculateUDPChecksum(&PacketBuffer);
								RecalculateIPChecksum (&PacketBuffer);
							}
						}
					}
					// Outgoing UDP NAT processing
					if(((bForceRouting) && (bNeedToBeRouted) &&(hAdapters[dwIndex]->m_NATState == CLIENT)&&(PacketBuffer.m_dwDeviceFlags == PACKET_FLAG_ON_RECEIVE))
						||
						((!bForceRouting) &&(hAdapters[dwIndex]->m_NATState == PROVIDER)&&(PacketBuffer.m_dwDeviceFlags == PACKET_FLAG_ON_SEND)))
					{
						CPortNATEntry* pUdpNE = NULL;
						// Try to find existing entry
						pUdpNE = pDlg->m_UdpNatTable.Find(pIpHeader->ip_src, pUdpHeader->th_sport, pIpHeader->ip_dst, pUdpHeader->th_dport);
						// If not found -> allocate a new one
						if (!pUdpNE)
						{
							pUdpNE = pDlg->m_UdpNatTable.Allocate(pIpHeader->ip_src, pUdpHeader->th_sport, pIpHeader->ip_dst, pUdpHeader->th_dport);
							
							if(pUdpNE)
							{
								pUdpNE->m_IpNAT = bForceRouting?pProviderCard->m_NATIp:hAdapters[dwIndex]->m_NATIp;
	 						}
						}
						// NAT processing
						if (pUdpNE)
						{
							pIpHeader->ip_src.S_un.S_addr = htonl(pUdpNE->m_IpNAT.S_un.S_addr);
							pUdpHeader->th_sport = htons(pUdpNE->m_usNATPort);
							RecalculateUDPChecksum (&PacketBuffer);
							RecalculateIPChecksum (&PacketBuffer);

							if (bForceRouting)
							{
								memcpy(pEthHeader->h_dest, MACServer, ETHER_ADDR_LENGTH);
								memcpy(pEthHeader->h_source, MACClient, ETHER_ADDR_LENGTH);

								PacketBuffer.m_dwDeviceFlags = PACKET_FLAG_ON_SEND;

								Request.hAdapterHandle = pProviderCard->m_hAdapter;

								goto finish;
							}
						}
					}
					// Incoming UDP packets processing
					if ((hAdapters[dwIndex]->m_NATState == PROVIDER)&&
					   (PacketBuffer.m_dwDeviceFlags == PACKET_FLAG_ON_RECEIVE))
					{
						CPortNATEntry* pUdpNE = pDlg->m_UdpNatTable.Map(pUdpHeader->th_dport);
						if (pUdpNE)
						{
							if (htonl(pUdpNE->m_IpDst.S_un.S_addr) == pIpHeader->ip_src.S_un.S_addr)
							{
								pIpHeader->ip_dst.S_un.S_addr = htonl(pUdpNE->m_IpSrc.S_un.S_addr);
								pUdpHeader->th_dport = htons(pUdpNE->m_usSrcPort);
								RecalculateUDPChecksum (&PacketBuffer);
								RecalculateIPChecksum (&PacketBuffer);
							}
						}
						
					}
				}

				// ICMP packets processing
				if (pIpHeader->ip_p == IPPROTO_ICMP)
				{
					// This is UDP packet, get UDP header pointer
					pIcmpHeader = (icmphdr*)(((PUCHAR)pIpHeader) + sizeof(DWORD)*pIpHeader->ip_hl);

					// Outgoing UDP NAT processing
					if(((bForceRouting) && (bNeedToBeRouted) &&(hAdapters[dwIndex]->m_NATState == CLIENT)&&(PacketBuffer.m_dwDeviceFlags == PACKET_FLAG_ON_RECEIVE))
						||
						((!bForceRouting) &&(hAdapters[dwIndex]->m_NATState == PROVIDER)&&(PacketBuffer.m_dwDeviceFlags == PACKET_FLAG_ON_SEND)))
					{
						CIcmpNATEntry* pIcmpNE = NULL;
						// Try to find existing entry
						pIcmpNE = pDlg->m_IcmpNatTable.Find(pIpHeader->ip_src, pIpHeader->ip_dst, pIcmpHeader->id);
						// If not found -> allocate a new one
						if (!pIcmpNE)
						{
							pIcmpNE = pDlg->m_IcmpNatTable.Allocate(pIpHeader->ip_src, pIpHeader->ip_dst, pIcmpHeader->id);
							
							if(pIcmpNE)
							{
								pIcmpNE->m_IpNAT = bForceRouting?pProviderCard->m_NATIp:hAdapters[dwIndex]->m_NATIp;
	 						}
						}
						// NAT processing
						if (pIcmpNE)
						{
							pIpHeader->ip_src.S_un.S_addr = htonl(pIcmpNE->m_IpNAT.S_un.S_addr);
							pIcmpHeader->id = htons(pIcmpNE->m_usNATIcmpId);
							RecalculateICMPChecksum (&PacketBuffer);
							RecalculateIPChecksum (&PacketBuffer);

							if (bForceRouting)
							{
								memcpy(pEthHeader->h_dest, MACServer, ETHER_ADDR_LENGTH);
								memcpy(pEthHeader->h_source, MACClient, ETHER_ADDR_LENGTH);

								PacketBuffer.m_dwDeviceFlags = PACKET_FLAG_ON_SEND;

								Request.hAdapterHandle = pProviderCard->m_hAdapter;

								goto finish;
							}
						}
					}
					// Incoming ICMP packets processing
					if ((hAdapters[dwIndex]->m_NATState == PROVIDER)&&
					   (PacketBuffer.m_dwDeviceFlags == PACKET_FLAG_ON_RECEIVE))
					{
						CIcmpNATEntry* pIcmpNE = pDlg->m_IcmpNatTable.Map(pIcmpHeader->id);
						if (pIcmpNE)
						{
							if (htonl(pIcmpNE->m_IpDst.S_un.S_addr) == pIpHeader->ip_src.S_un.S_addr)
							{
								pIpHeader->ip_dst.S_un.S_addr = htonl(pIcmpNE->m_IpSrc.S_un.S_addr);
								pIcmpHeader->id = htons(pIcmpNE->m_usIcmpId);
								RecalculateICMPChecksum (&PacketBuffer);
								RecalculateIPChecksum (&PacketBuffer);
							}
						}
						
					}
				}
				
			}
finish:
			// Reinject packet into the stack
			if (PacketBuffer.m_dwDeviceFlags == PACKET_FLAG_ON_SEND)
			{
				// Place packet on the network interface
				pDlg->m_NdisApi.SendPacketToAdapter(&Request);
			}
			else
			{
				// Indicate packet to MSTCP
				pDlg->m_NdisApi.SendPacketToMstcp(&Request);
			}

			Request.hAdapterHandle = hAdapters[dwIndex]->m_hAdapter;
		}

		::ResetEvent(hEvents[dwIndex]);

		

	}while (dwIndex);

	// Free all NAT entries
	pDlg->m_TcpNatTable.RemoveAll();
	pDlg->m_UdpNatTable.RemoveAll();

	for (unsigned i = 1; i < dwActiveAdaptersCount; ++i)
	{
		Mode.dwFlags = 0;
		Mode.hAdapterHandle = hAdapters[i]->m_hAdapter;

		// Set NULL event to release previously set event object
		pDlg->m_NdisApi.SetPacketEvent(hAdapters[i]->m_hAdapter, NULL);

		// Close Event
		if (hEvents[i])
			CloseHandle ( hEvents[i] );

		// Set default adapter mode
		pDlg->m_NdisApi.SetAdapterMode(&Mode);

		// Empty adapter packets queue
		pDlg->m_NdisApi.FlushAdapterPacketQueue (hAdapters[i]->m_hAdapter);
	}

	_endthreadex( 0 );
	return 0;
}

BOOL CsnatDlg::IsNeedToForceRouting(BYTE *MACAddress, DWORD dwDestIp, DWORD dwProviderIndex)
{
	static BYTE BroadcastAddress[ETHER_ADDR_LENGTH] ={0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; 
	
	if(!memcmp(MACAddress, BroadcastAddress, ETHER_ADDR_LENGTH))
		return FALSE;

	DWORD dwNextHopIndex = 0;

	GetBestInterface(dwDestIp, &dwNextHopIndex);

	if ((dwNextHopIndex == dwProviderIndex))
	{
		return TRUE;
	}

	return FALSE;
}

int CsnatDlg::UpdateDNSByIp(int nIp)
{
	TCHAR    achKey[64];   // buffer for subkey name
	DWORD    cbName = 64;  // size of name string 

	DWORD  retCode; 
	DWORD  dwType;
	DWORD	dwSize = 0;

	DWORD nParameters = 0;
	DWORD nInterfaces = 0;

	TCHAR  achInterface[MAX_STRING]; 
	TCHAR  achValue[MAX_STRING]; 
	CHAR  achIpAddr[MAX_STRING]; 
	CHAR  achDnsIpAddr[MAX_STRING]; 
	DWORD  cchValue = MAX_STRING; 

	HKEY hKey;
	HKEY hSubKey;

	int DNSIp = 0;


	if( RegOpenKeyEx( HKEY_LOCAL_MACHINE, TEXT("SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces"), 0, KEY_READ, &hKey) == ERROR_SUCCESS)
	{
		while(TRUE) 
		{
			cbName = 64;

			retCode = RegEnumKeyEx(hKey, nInterfaces, achKey, &cbName, NULL, NULL, NULL, NULL); 

			if (retCode == ERROR_SUCCESS) 
			{
				achInterface[0] = '\0';

				_tcscat_s(achInterface, TEXT("SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\"));

				_tcscat_s(achInterface, achKey);

				if( RegOpenKeyEx( HKEY_LOCAL_MACHINE, achInterface, 0, KEY_QUERY_VALUE, &hSubKey) == ERROR_SUCCESS)
				{
					nParameters = 0;

					while(TRUE) 
					{ 
						cchValue = MAX_STRING; 

						retCode = RegEnumValue(hSubKey, nParameters, achValue, &cchValue, NULL, NULL, NULL, NULL);

						if (retCode == ERROR_SUCCESS ) 
						{ 
							if((!_tcscmp(achValue, _T("IPAddress"))) || (!_tcscmp(achValue, _T("DhcpIPAddress"))))
							{
								dwSize =  MAX_STRING;

								if(RegQueryValueExA( hSubKey, achValue, 0, &dwType, (LPBYTE) achIpAddr, &dwSize) == ERROR_SUCCESS)
								{
									BOOL bFound  = FALSE;
									char *pIpStr = achIpAddr;
									int  nShift = 0;

									while(TRUE)
									{
										if(inet_addr(pIpStr) == nIp)
										{
											bFound = TRUE;
											break;
										}
										else
										{
											nShift = (int)strlen(pIpStr) + 1;

											if(nShift != dwSize)
											{
												pIpStr += nShift;

												dwSize -= nShift; 
											}
											else
											{
												break;
											}
										}
									}

									if(bFound)
									{
										dwSize =  MAX_STRING;

										if(RegQueryValueExA( hSubKey, _T("NameServer"), 0, &dwType, (LPBYTE) achDnsIpAddr, &dwSize) == ERROR_SUCCESS)
										{
											if(achDnsIpAddr[0] == 0) //pure string
											{
												dwSize =  MAX_STRING;

												RegQueryValueExA( hSubKey, _T("DhcpNameServer"), 0, &dwType, (LPBYTE) achDnsIpAddr, &dwSize);

											}
										}

										char* pFirstDnsEnd = strchr(achDnsIpAddr, 32);

										if(pFirstDnsEnd)
										{
											*pFirstDnsEnd = 0;
										}
										else
										{
											pFirstDnsEnd = strchr(achDnsIpAddr, ',');

											if(pFirstDnsEnd)
											{
												*pFirstDnsEnd = 0;
											}
										}

										DNSIp = inet_addr(achDnsIpAddr);

										break;
									}

								}


							}

							nParameters++;
						}
						else 
						{
							break;
						}

					}

					RegCloseKey(hSubKey);
				}

				nInterfaces++;
			}
			else 
			{
				break;
			}
		}

		RegCloseKey(hKey);
	} 


	return DNSIp;
}

// Retrieves DNS IP address using IP helper API
int CsnatDlg::GetDNSIp(void)
{
	PFIXED_INFO pInfo = NULL;
	DWORD dwInfoSize = 0;
	in_addr DNSIp;

	if(ERROR_BUFFER_OVERFLOW == GetNetworkParams(pInfo, &dwInfoSize))
	{
		pInfo = (PFIXED_INFO)::HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwInfoSize);

		if (ERROR_SUCCESS == GetNetworkParams(pInfo, &dwInfoSize))
		{
			DNSIp.S_un.S_addr = inet_addr((LPCSTR)pInfo->DnsServerList.IpAddress.String);
			
		}

		if (pInfo)
			::HeapFree(GetProcessHeap(), 0, pInfo);
	}

	return DNSIp.S_un.S_addr;
}

void CsnatDlg::OnClose()
{
	// Terminate working thread here
	if (m_hNATThread)
	{
		::SetEvent(m_hNATTerminateEvent);
		::WaitForSingleObject(m_hNATThread, INFINITE);
		m_hNATThread = NULL;
	}
	
	CDialog::OnClose();
}
