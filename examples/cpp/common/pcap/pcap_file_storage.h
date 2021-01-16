#pragma once

#include "pcap.h"

namespace pcap
{
	// --------------------------------------------------------------------------------
	/// <summary>
	/// PCAP format packet logger
	/// </summary>
	// --------------------------------------------------------------------------------
	class pcap_file_storage
	{
	public:
		explicit pcap_file_storage(const std::string& file_name)
		{
			open(file_name);
		}
		
		pcap_file_storage() = default;


		pcap_file_storage(const pcap_file_storage& other) = delete;

		pcap_file_storage(pcap_file_storage&& other) noexcept = delete;

		pcap_file_storage& operator=(const pcap_file_storage& other) = delete;

		pcap_file_storage& operator=(pcap_file_storage&& other) noexcept = delete;

		~pcap_file_storage()
		{
			try
			{
				if (file_stream_)
					file_stream_.close();
			}
			catch(...){}
		}
		
		// ReSharper disable once CppNonExplicitConversionOperator
		operator bool() const { return file_stream_ ? true: false; }

		void open(const std::string& file_name)
		{
			if (file_stream_)
				file_stream_.close();
			
			file_stream_.open(file_name, std::ofstream::binary | std::ofstream::out | std::ofstream::trunc);

			if (file_stream_)
			{
				const pcap::pcap_file_header header{ 2,4,0,0,MAX_ETHER_FRAME,pcap::LINKTYPE_ETHERNET };
				file_stream_ << header;
			}
		}

		pcap_file_storage& operator<<(const INTERMEDIATE_BUFFER& buffer)
		{
			static std::mutex lock;  // NOLINT(clang-diagnostic-exit-time-destructors)
			static auto last_time_stamp = time(nullptr);
			static uint32_t sequence = 0;

			std::lock_guard<std::mutex> write_lock(lock);
			
			const auto current_time = time(nullptr);
			if (current_time == last_time_stamp)
			{
				++sequence;
			}
			else
			{
				last_time_stamp = current_time;
				sequence = 0;
			}

			const auto* const ethernet_header = reinterpret_cast<char const*>(buffer.m_IBuffer);

			file_stream_ << pcap_record_header(static_cast<const uint32_t>(current_time), sequence,
			                                         buffer.m_Length, buffer.m_Length, ethernet_header);
			return *this;
		}

	private:
		std::ofstream file_stream_;
	};
}
