// --------------------------------------------------------------------------------
/// <summary>
/// Module Name:  EthernetBridge.h 
/// Abstract: EthernetBridge class interface
/// </summary>
// --------------------------------------------------------------------------------

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


class ethernet_bridge final : public CNdisApi
{
public:
	ethernet_bridge() noexcept : CNdisApi() { initialize_network_interfaces(); }
	virtual ~ethernet_bridge() { stop_bridge(); }

	// ********************************************************************************
	/// <summary>
	/// Starts bridging for the selected interfaces
	/// </summary>
	/// <param name="interfaces">indexes of network interfaces to bridge</param>
	/// <returns>boolean status of the operation</returns>
	// ********************************************************************************
	bool start_bridge(std::vector<size_t> const& interfaces);

	// ********************************************************************************
	/// <summary>
	/// Stops bridging
	/// </summary>
	// ********************************************************************************
	void stop_bridge();

	// ********************************************************************************
	/// <summary>
	/// Queries list of available network interfaces
	/// </summary>
	/// <returns>vector of pairs of strings representing internal and friendly network 
	/// interface names</returns>
	// ********************************************************************************
	std::vector<std::pair<string, string>> get_interface_list();

private:
	// ********************************************************************************
	/// <summary>
	/// Queries the index of the network interface to forward packet with the supplied 
	/// destination MAC address
	/// </summary>
	/// <param name="address">MAC address reference</param>
	/// <returns></returns>
	// ********************************************************************************
	std::optional<std::size_t> find_target_adapter_by_mac(net::mac_address const& address);

	// ********************************************************************************
	/// <summary>
	/// Stores network interface index for the supplied MAC address
	/// </summary>
	/// <param name="index">index of the network interface</param>
	/// <param name="address">MAC address to store behind the interface index</param>
	/// <returns></returns>
	// ********************************************************************************
	bool update_target_adapter_by_mac(std::size_t index, net::mac_address const& address);

	// ********************************************************************************
	/// <summary>
	/// Packet reading and forwarding thread
	/// </summary>
	/// <param name="index">network interface index to read packets from</param>
	// ********************************************************************************
	void bridge_working_thread(size_t index);

	// ********************************************************************************
	/// <summary>
	/// Initializes available network interfaces
	/// </summary>
	// ********************************************************************************
	void initialize_network_interfaces();

	/// <summary>Bridge running flag</summary>
	std::atomic_flag is_running_ = ATOMIC_FLAG_INIT;

	/// <summary>List of network interfaces available for bridging</summary>
	std::vector<unique_ptr<network_adapter>> network_interfaces_;
	
	/// <summary>vector of working threads</summary>
	std::vector<std::thread> working_threads_;

	/// <summary>vector of bridged network interfaces</summary>
	std::vector<std::size_t> bridged_interfaces_;
	
	/// <summary>has table to store MAC address -> adapter index association</summary>
	std::unordered_map<net::mac_address, std::size_t> mac_table_;

	/// <summary>synchronization lock for the hash table above</summary>
	std::shared_mutex mac_table_lock_;
};
