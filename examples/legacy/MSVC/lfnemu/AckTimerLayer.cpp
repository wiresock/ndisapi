#include "StdAfx.h"
#include "AckTimerLayer.h"

#define min(a, b)  (((a) < (b)) ? (a) : (b))

#define HASH_SIZE					16

namespace acktl {

// AckTimer Layer variables

typedef struct _FLOW_STRUCTURE
{
	DWORD				m_dwIP;
	DWORD				m_dwAdapterHandle;
	USHORT				m_usPeerTCPPort;	
	USHORT				m_usLocalTCPPort;
	DWORD				m_dwLastAck;
	DWORD				m_dwLastSentSeqNo;
	DWORD				m_dwLastRcvACKNo;
	DWORD				m_dwLastRcvSeqNo;
	DWORD				m_dwLastRcvPktTime;
	DWORD				m_dwStartTime;
	USHORT				m_usMaxRcvWindowSize;
	u_char				m_LastRcvPkt[MAX_ETHER_FRAME];
	ULONG				m_usLastRcvPktSize;
} FLOW_STRUCTURE, *PFLOW_STRUCTURE;

DWORD				dwTimeout;
DWORD				dwDupNum = 0;
std::vector<PFLOW_STRUCTURE> TCP_FLOW[HASH_SIZE];

void (*nextLayerDown)(PETH_REQUEST pRequest) = 0;
void (*nextLayerUp)(PETH_REQUEST pRequest) = 0;

// End of AckTimer Layer variables

int initLayer(UINT aTimeout, void* aNextLayerDown, void* aNextLayerUp)
{
	if (!aNextLayerDown || !aNextLayerUp)
		return false;

	dwTimeout = aTimeout;
	nextLayerDown = (void (*) (PETH_REQUEST)) aNextLayerDown;
	nextLayerUp   = (void (*) (PETH_REQUEST)) aNextLayerUp;

	return true;
}

//Send 3 + dwDupNum DUP ACK packets
void SendDupAck(PFLOW_STRUCTURE pStream, bool Up)
{
/*	ether_header*		pEthHeader;
	iphdr*				pIpHeader;
	tcphdr_ptr			pTcpHeader;
*/	
	INTERMEDIATE_BUFFER	AckBuffer;

	ZeroMemory(&AckBuffer, sizeof(INTERMEDIATE_BUFFER));

	ETH_REQUEST			RequestBuffer;

	memmove(AckBuffer.m_IBuffer, pStream->m_LastRcvPkt, 
			min(pStream->m_usLastRcvPktSize, MAX_ETHER_FRAME));
		
	AckBuffer.m_dwDeviceFlags = (Up)? PACKET_FLAG_ON_RECEIVE : PACKET_FLAG_ON_SEND;
	AckBuffer.m_Length	= min(pStream->m_usLastRcvPktSize, MAX_ETHER_FRAME);

	ZeroMemory ( &RequestBuffer, sizeof(ETH_REQUEST) );
	
	RequestBuffer.EthPacket.Buffer = &AckBuffer;
		
	RequestBuffer.hAdapterHandle = (HANDLE)pStream->m_dwAdapterHandle;

	for(UINT n = 0; n < 3 + dwDupNum; n++)
	{
		if (Up && nextLayerUp)
			nextLayerUp(&RequestBuffer);
		else if (!Up && nextLayerDown)
			nextLayerDown(&RequestBuffer);
	}

	_tprintf(_T("Requesting Fast Retransmission\n"));
}

//
// Delete the flow structure corresponding to the given TCP/IP pair
//
void DeleteFlowDescriptor(ULONG peerIpAddress, 
								   USHORT peerTcpPort,
								   USHORT localTcpPort)
{
	std::vector<PFLOW_STRUCTURE	>::iterator theIterator;

	if(TCP_FLOW[peerIpAddress % HASH_SIZE].empty())
		return;
	
	for (theIterator = TCP_FLOW[peerIpAddress % HASH_SIZE].begin(); 
			theIterator != TCP_FLOW[peerIpAddress % HASH_SIZE].end();
			theIterator++)
	{
						
		if (((*theIterator)->m_dwIP == peerIpAddress)
				&& ((*theIterator)->m_usPeerTCPPort == peerTcpPort)
				&& ((*theIterator)->m_usLocalTCPPort == localTcpPort))
		{
			TCP_FLOW[peerIpAddress % HASH_SIZE].erase(theIterator);
			return;
		}
	}// for
}

//
// Find and return the flow structure corresponding to the given TCP/IP pair
//
PFLOW_STRUCTURE FindFlowDescriptor(ULONG peerIpAddress, 
								   USHORT peerTcpPort,
								   USHORT localTcpPort)
{
	std::vector<PFLOW_STRUCTURE	>::iterator theIterator;

	if(TCP_FLOW[peerIpAddress % HASH_SIZE].empty())
		return NULL;
	
	for (theIterator = TCP_FLOW[peerIpAddress % HASH_SIZE].begin(); 
			theIterator != TCP_FLOW[peerIpAddress % HASH_SIZE].end();
			theIterator++)
	{
						
		if (((*theIterator)->m_dwIP == peerIpAddress)
			&& ((*theIterator)->m_usPeerTCPPort == peerTcpPort)
			&& ((*theIterator)->m_usLocalTCPPort == localTcpPort))
			return *theIterator;
	}

	return NULL;
}

//
// Function controls all tcp's strems statements
//
void TCPStreamsCheck(PETH_REQUEST pRequest)
{
	ULONG				peerIpAddress, now = ::GetTickCount();
	USHORT				peerTCPPort, localTCPPort;
	PFLOW_STRUCTURE		pStream = NULL;
	BOOL				connectionApproved = FALSE;
	
	PINTERMEDIATE_BUFFER pPacketBuffer = pRequest->EthPacket.Buffer;
	HANDLE hAdapterHandle = pRequest->hAdapterHandle;

	ether_header*	pEthHeader = (ether_header*) pPacketBuffer->m_IBuffer;
	iphdr*			pIpHeader = (iphdr*) (pPacketBuffer->m_IBuffer + 
			ETHER_HEADER_LENGTH);

	if (!((ntohs(pEthHeader->h_proto) == ETH_P_IP) && (pIpHeader->ip_p == 
			IPPROTO_TCP)))
		return;

	tcphdr *pTcpHeader = (tcphdr *) (((PUCHAR) pIpHeader) + sizeof(DWORD) *
			pIpHeader->ip_hl);			

	// Take peer's IP address and TCP ports. 
	if (pPacketBuffer->m_dwDeviceFlags == PACKET_FLAG_ON_SEND)
	{
		peerIpAddress = pIpHeader->ip_dst.S_un.S_addr;
		peerTCPPort = pTcpHeader->th_dport;
		localTCPPort = pTcpHeader->th_sport;
	}
	else
	{
		peerIpAddress = pIpHeader->ip_src.S_un.S_addr;
		peerTCPPort = pTcpHeader->th_sport;
		localTCPPort = pTcpHeader->th_dport;
	}

	/* Check for connection approval from both sites. We shouldn't allocate
	* resources until we see a full Syn->, <-Syn-Ack, Ack->. For simplicity,
	* we just check for SYN-ACK, but this may be vulnerable to DoS. DOUBLE_CHECK */
	if (pTcpHeader->th_flags == (TH_SYN | TH_ACK))
		connectionApproved = true;
	
	pStream = FindFlowDescriptor(peerIpAddress, peerTCPPort, localTCPPort);

	if (connectionApproved){
				
		if (!pStream){
			pStream = new FLOW_STRUCTURE;
			TCP_FLOW[peerIpAddress % HASH_SIZE].push_back(pStream);
		}

		pStream->m_dwIP					=	peerIpAddress;
		pStream->m_usPeerTCPPort		=	peerTCPPort;
		pStream->m_usLocalTCPPort		=	localTCPPort;
		pStream->m_dwAdapterHandle		=   0;
		pStream->m_dwLastRcvPktTime		=	0;
		pStream->m_dwStartTime			=   0;
		pStream->m_dwLastAck			=	0;
		pStream->m_usMaxRcvWindowSize	=	pTcpHeader->th_win;
		
		memmove(pStream->m_LastRcvPkt, pPacketBuffer->m_IBuffer, 
				pPacketBuffer->m_Length);
		pStream->m_usLastRcvPktSize = pPacketBuffer->m_Length; 
	}
	
	if ((pPacketBuffer->m_dwDeviceFlags == PACKET_FLAG_ON_SEND)
		&&((pTcpHeader->th_flags & TH_ACK) == TH_ACK)
		&&(pStream))
			pStream->m_dwLastAck = pTcpHeader->th_ack;

	// Save largest sent Seq Number for this connection
	if ((pPacketBuffer->m_dwDeviceFlags == PACKET_FLAG_ON_SEND)	&& (pStream))
	{
		pStream->m_dwLastSentSeqNo = ntohl(pTcpHeader->th_seq);
	}

	if ((pPacketBuffer->m_dwDeviceFlags == PACKET_FLAG_ON_SEND)
		&& ((pTcpHeader->th_flags & TH_ACK) == TH_ACK)
		&& ((pTcpHeader->th_flags & TH_SYN) == 0)
		&&(pStream)
		&&(pStream->m_dwLastRcvPktTime == 0)
		&&(!pStream->m_dwAdapterHandle))
		{
			
			pStream->m_dwAdapterHandle		=   (DWORD)hAdapterHandle;	
			
			_tprintf(_T("TCP connection established : source IP:port - "
					"%d.%d.%d.%d:%d :destination IP:port  - %d.%d.%d.%d:%d, "
					"current time = %d.\n"),
								pStream->m_LastRcvPkt[0x1a],
								pStream->m_LastRcvPkt[0x1b],
								pStream->m_LastRcvPkt[0x1c],
								pStream->m_LastRcvPkt[0x1d],
								ntohs(pStream->m_usLocalTCPPort),
								pStream->m_LastRcvPkt[0x1e],
								pStream->m_LastRcvPkt[0x1f],
								pStream->m_LastRcvPkt[0x20],
								pStream->m_LastRcvPkt[0x21],
								ntohs(pStream->m_usPeerTCPPort),
								now);
			
			pStream->m_dwStartTime = now;
			return;
		}
			
	if ((pPacketBuffer->m_dwDeviceFlags == PACKET_FLAG_ON_RECEIVE)
			&& ((pTcpHeader->th_flags & (TH_ACK | TH_SYN)) == TH_ACK)
			&& (pStream))
	{
		if ((pStream->m_dwLastRcvPktTime != 0) 
				&& (now - pStream->m_dwLastRcvPktTime > dwTimeout)
				&& (pStream->m_dwLastSentSeqNo + 1 > pStream->m_dwLastRcvACKNo))
		{
			SendDupAck(pStream, true);
		}

		pStream->m_dwLastRcvACKNo = ntohl(pTcpHeader->th_ack);
		pStream->m_dwLastRcvSeqNo = ntohl(pTcpHeader->th_seq);
		memmove(pStream->m_LastRcvPkt, pPacketBuffer->m_IBuffer, 
				pPacketBuffer->m_Length);
		pStream->m_usLastRcvPktSize = pPacketBuffer->m_Length; 
		pStream->m_dwLastRcvPktTime = now;
		pStream->m_dwStartTime = 0;
	}
	
	if ((((pTcpHeader->th_flags & TH_FIN) == TH_FIN) 
			|| ((pTcpHeader->th_flags & TH_RST) == TH_RST))
			&& (pStream))
	{
		DeleteFlowDescriptor(peerIpAddress, peerTCPPort, localTCPPort);
		_tprintf(_T("TCP connection finished : source IP:port - "
				"%d.%d.%d.%d:%d :destination IP:port  - %d.%d.%d.%d:%d, "
				"current time = %d.\n"),
							pStream->m_LastRcvPkt[0x1a],
							pStream->m_LastRcvPkt[0x1b],
							pStream->m_LastRcvPkt[0x1c],
							pStream->m_LastRcvPkt[0x1d],
							ntohs(pStream->m_usLocalTCPPort),
							pStream->m_LastRcvPkt[0x1e],
							pStream->m_LastRcvPkt[0x1f],
							pStream->m_LastRcvPkt[0x20],
							pStream->m_LastRcvPkt[0x21],
							ntohs(pStream->m_usPeerTCPPort),
							now);
	} //if
}

int haltLayer(void)
{
	std::vector<PFLOW_STRUCTURE	>::iterator theIterator;

	for(int nCount = 0; nCount < HASH_SIZE; nCount++)
	{
		if(TCP_FLOW[nCount].empty())
			continue;

		for (theIterator = TCP_FLOW[nCount].begin(); 
				theIterator != TCP_FLOW[nCount].end(); theIterator++)
			delete *theIterator;

		TCP_FLOW[nCount].clear();
				
	}
	return true;
}

void AckTimerLayer(PETH_REQUEST pRequest)
{
	TCPStreamsCheck(pRequest);

	if (pRequest->EthPacket.Buffer->m_dwDeviceFlags == PACKET_FLAG_ON_SEND){
		if (nextLayerDown)
			nextLayerDown(pRequest);
	}
	else {
		if (nextLayerUp)
			nextLayerUp(pRequest);
	}
}

} // namespace acktl 