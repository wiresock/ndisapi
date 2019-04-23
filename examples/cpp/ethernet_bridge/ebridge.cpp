// --------------------------------------------------------------------------------
/// <summary>
/// Module Name:  ebridge.cpp    
/// Abstract: Defines the entry point for the console application
/// </summary>
// --------------------------------------------------------------------------------

#include "stdafx.h"

int main(int argc, char* argv[])
{
	ethernet_bridge ether_bridge;
	size_t num, index = 0;

	// Check if driver was loaded properly
	if (!ether_bridge.IsDriverLoaded())
	{
		cout << "Driver not installed on this system of failed to load. Please install WinpkFilter drivers first." << endl;
		return 0;
	}

	cout << "Available network interfaces:" << endl << endl;
	for (auto& e : ether_bridge.get_interface_list())
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
		if (ether_bridge.start_bridge(interfaces))
			cout << "Ethernet Bridge has started successfully!" << endl;
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

