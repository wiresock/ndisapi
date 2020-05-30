using System;
using NdisApiWrapper;

namespace FilterStats
{
    static class Program
    {
        static void Main(string[] args)
        {
            try
            {
                if (args.Length < 1)
                {
                    Console.WriteLine(
                        "Command line syntax:\r\n\tfilterstats.exe [DoReset] \r\n\tDoReset - 1 to reset filters counters / 0 - query counters without reset.");
                    return;
                }

                var reset = Convert.ToInt32(args[0]) == 1;

                var driverPtr = Ndisapi.OpenFilterDriver();
                if (!Ndisapi.IsDriverLoaded(driverPtr))
                {
                    Console.WriteLine("Driver not installed on this system of failed to load.");
                    return;
                }

                // Get number of filters loaded
                var filtersCount = 0u;
                Ndisapi.GetPacketFilterTableSize(driverPtr, ref filtersCount);

                Console.WriteLine("{0} filters loaded into the driver", filtersCount);

                if (filtersCount == 0) return;
                
                var filtersTable = new STATIC_FILTER_TABLE {m_TableSize = filtersCount};
                    
                // if reset flag is set then query filters table with reset and without reset otherwise
                if (reset)
                {
                    Ndisapi.GetPacketFilterTableResetStats(driverPtr, ref filtersTable);
                }
                else
                {
                    Ndisapi.GetPacketFilterTable(driverPtr, ref filtersTable);
                }

                Console.WriteLine("Statistics for the loaded filters:");

                for (var i = 0; i < filtersTable.m_TableSize; ++i)
                {
                    Console.WriteLine("Filter {0}: ", i);
                    Console.WriteLine("\tIncoming packets counter = {0}", filtersTable.m_StaticFilters[i].m_PacketsIn);
                    Console.WriteLine("\tIncoming bytes counter = {0}", filtersTable.m_StaticFilters[i].m_BytesIn);
                    Console.WriteLine("\tOutgoing packets counter = {0}", filtersTable.m_StaticFilters[i].m_PacketsOut);
                    Console.WriteLine("\tOutgoing bytes counter = {0}", filtersTable.m_StaticFilters[i].m_BytesOut);
                    Console.WriteLine("\tLast reset = {0}", new DateTime(1980, 1, 1).AddSeconds(filtersTable.m_StaticFilters[i].m_LastReset).ToLocalTime());
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }
        }
    }
}
