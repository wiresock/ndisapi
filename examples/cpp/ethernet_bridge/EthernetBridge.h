/*************************************************************************/
/*              Copyright (c) 2000-2018 NT Kernel Resources.             */
/*                           All Rights Reserved.                        */
/*                          http://www.ntkernel.com                      */
/*                           ndisrd@ntkernel.com                         */
/*                                                                       */
/* Module Name:  EthernetBridge.h                                        */
/*                                                                       */
/* Abstract: EthernetBridge class interface                              */
/*                                                                       */
/* Environment:                                                          */
/*   User mode                                                           */
/*                                                                       */
/*************************************************************************/
#pragma once

//
// Medium the Ndis Driver is running on (OID_GEN_MEDIA_SUPPORTED/ OID_GEN_MEDIA_IN_USE).
//
enum class NdisMedium
{
	NdisMedium802_3,
	NdisMedium802_5,
	NdisMediumFddi,
	NdisMediumWan,
	NdisMediumLocalTalk,
	NdisMediumDix,              // defined for convenience, not a real medium
	NdisMediumArcnetRaw,
	NdisMediumArcnet878_2,
	NdisMediumAtm,
	NdisMediumWirelessWan,
	NdisMediumIrda,
	NdisMediumBpc,
	NdisMediumCoWan,
	NdisMedium1394,
	NdisMediumInfiniBand,
	NdisMediumTunnel,
	NdisMediumNative802_11,
	NdisMediumLoopback,
	NdisMediumWiMAX,
	NdisMediumIP,
	NdisMediumMax               // Not a real medium, defined as an upper-bound
};

//
// Physical Medium Type definitions. Used with OID_GEN_PHYSICAL_MEDIUM.
//
enum class NdisPhysicalMedium
{
	NdisPhysicalMediumUnspecified,
	NdisPhysicalMediumWirelessLan,
	NdisPhysicalMediumCableModem,
	NdisPhysicalMediumPhoneLine,
	NdisPhysicalMediumPowerLine,
	NdisPhysicalMediumDSL,      // includes ADSL and UADSL (G.Lite)
	NdisPhysicalMediumFibreChannel,
	NdisPhysicalMedium1394,
	NdisPhysicalMediumWirelessWan,
	NdisPhysicalMediumNative802_11,
	NdisPhysicalMediumBluetooth,
	NdisPhysicalMediumInfiniband,
	NdisPhysicalMediumWiMax,
	NdisPhysicalMediumUWB,
	NdisPhysicalMedium802_3,
	NdisPhysicalMedium802_5,
	NdisPhysicalMediumIrda,
	NdisPhysicalMediumWiredWAN,
	NdisPhysicalMediumWiredCoWan,
	NdisPhysicalMediumOther,
	NdisPhysicalMediumMax       // Not a real physical type, defined as an upper-bound
};


class EthernetBridge : public CNdisApi
{
public:
	EthernetBridge() noexcept : CNdisApi() { InitializeNetworkInterfaces(); }
	virtual ~EthernetBridge() { StopBridge(); }

	bool									StartBridge(std::vector<size_t> const& interfaces);
	void									StopBridge();
	std::vector<std::pair<string, string>>	GetInterfaceList();

private:
	std::optional<std::size_t>				FindTargetAdapterByMac(mac_address const& address);
	bool									UpdateTargetAdapterByMac(std::size_t index, mac_address const& address);
	void									BridgeWorkingThread(size_t);
	void									InitializeNetworkInterfaces();

	std::atomic_flag								m_bIsRunning = ATOMIC_FLAG_INIT;
	std::vector<unique_ptr<CNetworkAdapter>>		m_NetworkInterfaces; // List of network interfaces available for bridging
	std::vector<std::thread>						m_WorkingThreads;
	std::vector<std::size_t>						m_BridgedInterfaces;

	std::unordered_map<mac_address, std::size_t>	m_MacTable;
	std::shared_mutex								m_MacTableLock;
};
