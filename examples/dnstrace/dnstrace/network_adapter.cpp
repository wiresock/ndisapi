/*************************************************************************/
/*              Copyright (c) 2000-2018 NT Kernel Resources.             */
/*                           All Rights Reserved.                        */
/*                          http://www.ntkernel.com                      */
/*                           ndisrd@ntkernel.com                         */
/*                                                                       */
/* Module Name:  network_adapter.cpp                                     */
/*                                                                       */
/* Abstract: Network interface wrapper class defintions                  */
/*                                                                       */
/* Environment:                                                          */
/*   User mode                                                           */
/*                                                                       */
/*************************************************************************/

#include "stdafx.h"

void network_adapter::Release()
{
	// This function releases packets in the adapter queue and stops listening the interface
	m_Event.signal();

	// Reset adapter mode and flush the packet queue
	m_CurrentMode.dwFlags = 0;
	m_CurrentMode.hAdapterHandle = m_hAdapter;

	m_pApi->SetAdapterMode(&m_CurrentMode);
	m_pApi->FlushAdapterPacketQueue(m_hAdapter);
}

void network_adapter::SetMode(unsigned dwFlags)
{
	m_CurrentMode.dwFlags = dwFlags;
	m_CurrentMode.hAdapterHandle = m_hAdapter;

	m_pApi->SetAdapterMode(&m_CurrentMode);
}
