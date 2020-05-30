/*************************************************************************/
/*				Copyright (c) 2000-2013 NT Kernel Resources.		     */
/*                           All Rights Reserved.                        */
/*                          http://www.ntkernel.com                      */
/*                           ndisrd@ntkernel.com                         */
/*                                                                       */
/* Module Name:  ListAdapters main module                                */
/*                                                                       */
/* Abstract: Defines the entry point for the console application         */
/*                                                                       */
/*************************************************************************/

using System;
using System.Runtime.InteropServices;
using NdisApiWrapper;


namespace ListAdapters
{
    static class Program
    {
        static void Main()
        {
            try
            {
                var driverPtr = Ndisapi.OpenFilterDriver();

                var adapters = new TCP_AdapterList();
                GCHandle.Alloc(adapters);

                if ((Ndisapi.IsDriverLoaded(driverPtr)))
                {
                    Console.WriteLine("The following network interfaces are available to MSTCP:");
                    
                    var result = Ndisapi.GetTcpipBoundAdaptersInfo(driverPtr, ref adapters);
                    if(!result) throw new ApplicationException("Can't get TCP/IP bound adapters info");

                    for (var i = 0; i < adapters.m_nAdapterCount; i++)
                    {
                        Console.WriteLine("{0}) {1}", i + 1, adapters.GetName(i));
                        Console.WriteLine("\tInternal Name:\t {0}", adapters.GetInternalName(i));
                        Console.WriteLine( "\tCurrent MAC:\t {0}", adapters.GetMacAddressStr(i));
                        Console.WriteLine("\tMedium:\t 0x{0:X8}", adapters.m_nAdapterMediumList[i]);
                        Console.WriteLine("\tCurrent MTU:\t {0}", adapters.m_usMTU[i]);

                        // Set tunnel mode for the selected network iunterface
                        var mode = new ADAPTER_MODE {hAdapterHandle = adapters.m_nAdapterHandle[i]};
                        Ndisapi.GetAdapterMode(driverPtr, ref mode);

                        Console.WriteLine("\tCurrent adapter mode = 0x{0:X8}", mode.dwFlags);
                    }
                    Console.WriteLine("\n\nCurrent system wide MTU decrement = {0}", Ndisapi.GetMTUDecrement());
                    Console.WriteLine("Default adapter startup mode = 0x{0:X8}", Ndisapi.GetAdaptersStartupMode());

                }
                else
                {
                    Console.WriteLine("Helper driver failed to load or was not installed.");
                }

                Ndisapi.CloseFilterDriver(driverPtr);
            }

            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
            }
        }
    }
}
