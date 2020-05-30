/*************************************************************************/
/*				Copyright (c) 2000-2016 NT Kernel Resources.		     */
/*                           All Rights Reserved.                        */
/*                          http://www.ntkernel.com                      */
/*                           ndisrd@ntkernel.com                         */
/*                                                                       */
/* Module Name:  ndisrequest.cpp                                         */
/*                                                                       */
/* Abstract: Defines the entry point for the console application         */
/*                                                                       */
/*************************************************************************/

#include "stdafx.h"

#define OID_802_3_CURRENT_ADDRESS				0x01010102
#define OID_GEN_MAXIMUM_FRAME_SIZE              0x00010106

//
//	Required statistics
//
#define OID_GEN_XMIT_OK							0x00020101
#define OID_GEN_RCV_OK							0x00020102
#define OID_GEN_XMIT_ERROR						0x00020103
#define OID_GEN_RCV_ERROR						0x00020104
#define OID_GEN_RCV_NO_BUFFER					0x00020105

int main(int argc, char* argv[])
{
	_TCP_AdapterList	AdapterList;
	CNdisApi			api;

	api.GetTcpipBoundAdaptersInfo ( &AdapterList );

	// Query MAC address from interface request
	PPACKET_OID_DATA pCurrentMacRequest = (PPACKET_OID_DATA)new char[sizeof(PACKET_OID_DATA) + 5];

	// Query stat request
	PPACKET_OID_DATA pStatRequest = (PPACKET_OID_DATA)new char[sizeof(PACKET_OID_DATA) + sizeof(DWORD) - 1];

	pStatRequest->Length = sizeof(DWORD);
	
	for (unsigned i = 0; i < AdapterList.m_nAdapterCount; ++i)
	{
		pCurrentMacRequest->Length = 6;
		pCurrentMacRequest->Oid = OID_802_3_CURRENT_ADDRESS;
		pCurrentMacRequest->hAdapterHandle = AdapterList.m_nAdapterHandle[i];
		
		memset(pCurrentMacRequest->Data, 0, pCurrentMacRequest->Length);
	
		pStatRequest->hAdapterHandle = AdapterList.m_nAdapterHandle[i];

		api.NdisrdRequest(pCurrentMacRequest, FALSE);

		printf ("%d) Current MAC is %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", i+1, pCurrentMacRequest->Data[0], pCurrentMacRequest->Data[1], pCurrentMacRequest->Data[2], pCurrentMacRequest->Data[3], pCurrentMacRequest->Data[4], pCurrentMacRequest->Data[5]);

		pStatRequest->Oid = OID_GEN_MAXIMUM_FRAME_SIZE;

		if(api.NdisrdRequest (pStatRequest, FALSE))
			printf("\tMaximum Frame Size = %d\n", *((PDWORD)(pStatRequest->Data)));

		pStatRequest->Oid = OID_GEN_XMIT_OK;

		if (api.NdisrdRequest(pStatRequest, FALSE))
			printf("\tFrames transmitted without errors = %d\n", *((PDWORD)(pStatRequest->Data)));

		pStatRequest->Oid = OID_GEN_RCV_OK;

		if (api.NdisrdRequest(pStatRequest, FALSE))
			printf("\tFrames received without errors = %d\n", *((PDWORD)(pStatRequest->Data)));

		pStatRequest->Oid = OID_GEN_XMIT_ERROR;

		if (api.NdisrdRequest(pStatRequest, FALSE))
			printf("\tFrames that a NIC failed to transmit = %d\n", *((PDWORD)(pStatRequest->Data)));

		pStatRequest->Oid = OID_GEN_RCV_ERROR;

		if (api.NdisrdRequest(pStatRequest, FALSE))
			printf("\tFrames that a NIC have not indicated due to errors = %d\n", *((PDWORD)(pStatRequest->Data)));

	}

	delete[] (char*)pCurrentMacRequest;
	delete[] (char*)pStatRequest;

	return 0;
}

