/*************************************************************************/
/*              Copyright (c) 2000-2018 NT Kernel Resources.             */
/*                           All Rights Reserved.                        */
/*                          http://www.ntkernel.com                      */
/*                           ndisrd@ntkernel.com                         */
/*                                                                       */
/* Module Name:  ebridge.cpp                                             */
/*                                                                       */
/* Abstract: Defines the entry point for the console application         */
/*                                                                       */
/* Environment:                                                          */
/*   User mode                                                           */
/*                                                                       */
/*************************************************************************/

#include "stdafx.h"

int main(int argc, char* argv[])
{
	EthernetBridge eBridge;
	size_t num, index = 0;

	//
	// Check if driver us loaded properly
	if (!eBridge.IsDriverLoaded())
	{
		cout << "Driver not installed on this system of failed to load. Please install WinpkFilter drivers first." << endl;
		return 0;
	}

	cout << "Available network interfaces:" << endl << endl;
	for (auto& e : eBridge.GetInterfaceList())
	{
		cout << ++index <<") " << e.first << endl;
	}

	cout << endl;

	cout << "Enter number of interfaces to bridge: ";
	cin >> num;

	std::vector<size_t> interfaces;
	interfaces.reserve(num);

	for (size_t i = 0; i < num; i++)
	{
		cout << "Enter interface index:";
		cin >> index;
		interfaces.push_back(index - 1);
	}

	try {
		if (eBridge.StartBridge(interfaces))
			cout << "Ethernet Bridge has started succesfully!" << endl;
		else
			cout << "Ethernet Bridge has failed to start!" << endl;
	}
	catch (const std::system_error& error)
	{
		std::cout << "Error: " << error.code()
			<< " - " << error.code().message() << '\n';

		return 0;
	}

	cout << "Press any key to stop bridging" << endl;
 
	std::ignore = _getch();

	printf("Exiting... \n");
 
	return 0;
}

