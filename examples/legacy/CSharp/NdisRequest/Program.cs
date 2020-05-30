using System;
using System.Runtime.InteropServices;
using NdisApiWrapper;

namespace NdisRequest
{
    static class Program
    {
        private const int Oid8023CurrentAddress = 0x01010102;
        private const int OidGenXmitOk = 0x00020101;
        private const int OidGenRcvOk = 0x00020102;
        private const int OidGenXmitError = 0x00020103;
        private const int OidGenRcvError = 0x00020104;

        static void Main()
        {
            try
            {
                var ndisHandler = Ndisapi.OpenFilterDriver();
                var adapterList = new TCP_AdapterList();

                var currentMacRequest = new PACKET_OID_DATA();
                var statRequest = new PACKET_OID_DATA();
                statRequest.Length = sizeof (int);

                GCHandle.Alloc(adapterList);
                if (!(Ndisapi.IsDriverLoaded(ndisHandler))) throw new Exception("Driver failed to load or was not installed.");

                var result = Ndisapi.GetTcpipBoundAdaptersInfo(ndisHandler, ref adapterList);
                if (!result) throw new ApplicationException("Cannot get network adapters list.");

                for (var i = 0; i < adapterList.m_nAdapterCount; i++)
                {
                    currentMacRequest.Length = 6;
                    currentMacRequest.Oid = Oid8023CurrentAddress;
                    currentMacRequest.hAdapterHandle = adapterList.m_nAdapterHandle[i];

                    statRequest.hAdapterHandle = adapterList.m_nAdapterHandle[i];

                    if(!Ndisapi.NdisrdRequest(ndisHandler, ref currentMacRequest, false)) continue;

                    var data = currentMacRequest.GetData();
                    Console.WriteLine("{0}) Current MAC is {1:X2}-{2:X2}-{3:X2}-{4:X2}-{5:X2}-{6:X2} ", i + 1, data[0], data[1], data[2], data[3], data[4], data[5]);

                    statRequest.Oid = OidGenXmitOk;

                    if (Ndisapi.NdisrdRequest(ndisHandler, ref statRequest, false))
                    {
                        Console.WriteLine("\tFrames transmitted without errors = {0}", BitConverter.ToUInt32(statRequest.GetData(), 0));
                    }

                    statRequest.Oid = OidGenRcvOk;

                    Ndisapi.NdisrdRequest(ndisHandler, ref statRequest, false);
                    Console.WriteLine("\tFrames received without errors = {0}", BitConverter.ToUInt32(statRequest.GetData(), 0));

                    statRequest.Oid = OidGenXmitError;

                    Ndisapi.NdisrdRequest(ndisHandler, ref statRequest, false);
                    Console.WriteLine("\tFrames that a NIC failed to transmit = {0}", BitConverter.ToUInt32(statRequest.GetData(), 0));

                    statRequest.Oid = OidGenRcvError;

                    Ndisapi.NdisrdRequest(ndisHandler, ref statRequest, false);
                    Console.WriteLine("\tFrames that a NIC have not indicated due to errors = {0}", BitConverter.ToUInt32(statRequest.GetData(), 0));

                }

                Ndisapi.CloseFilterDriver(ndisHandler);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }
        }
    }
}

