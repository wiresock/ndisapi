/*************************************************************************/
/*              Copyright (c) 2000-2018 NT Kernel Resources.             */
/*                           All Rights Reserved.                        */
/*                          http://www.ntkernel.com                      */
/*                           ndisrd@ntkernel.com                         */
/*                                                                       */
/* Module Name:  simple_packet_filter.h                                  */
/*                                                                       */
/* Abstract: Simple packet filter class declaration                      */
/*                                                                       */
/* Environment:                                                          */
/*   User mode                                                           */
/*                                                                       */
/*************************************************************************/

#pragma once
inline const size_t maximum_packet_block = 512;

enum class PacketAction
{
	pass,
	drop
};

class simple_packet_filter : public CNdisApi
{
	simple_packet_filter() : CNdisApi() { initialize_network_interfaces(); }

public:
	template<typename F1, typename F2>
	simple_packet_filter(F1 In, F2 Out) : simple_packet_filter()
	{
		filter_incoming_packet = In;
		filter_outgoing_packet = Out;
	}

	virtual ~simple_packet_filter() { stop_filter(); }

	bool start_filter(size_t);
	bool stop_filter();
	std::vector<std::string> get_interface_list();

private:
	void filter_working_thread();
	void initialize_network_interfaces();

	std::function<PacketAction(INTERMEDIATE_BUFFER&)> filter_outgoing_packet = nullptr;
	std::function<PacketAction(INTERMEDIATE_BUFFER&)> filter_incoming_packet = nullptr;

	std::atomic_flag m_bIsRunning = ATOMIC_FLAG_INIT;
	std::vector<std::unique_ptr<network_adapter>> m_NetworkInterfaces;
	std::thread m_WorkingThread;
	size_t m_Adapter = 0;
};

