/*************************************************************************/
/*				Copyright (c) 2000-2016 NT Kernel Resources.		     */
/*                           All Rights Reserved.                        */
/*                          http://www.ntkernel.com                      */
/*                           ndisrd@ntkernel.com                         */
/* Module Name:  snat.h					                                 */
/*                                                                       */
/* Abstract: main header file for the SNAT application 	                 */
/*                                                                       */
/*                                                                       */
/*************************************************************************/

#pragma once

#ifndef __AFXWIN_H__
	#error include 'stdafx.h' before including this file for PCH
#endif

#include "resource.h"		// main symbols


// CsnatApp:
// See snat.cpp for the implementation of this class
//

class CsnatApp : public CWinApp
{
public:
	CsnatApp();

// Overrides
	public:
	virtual BOOL InitInstance();

// Implementation

	DECLARE_MESSAGE_MAP()
};

extern CsnatApp theApp;