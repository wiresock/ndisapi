#pragma once

namespace winsys {

	// --------------------------------------------------------------------------------
	/// <summary>
	/// simple Wrapper for Windows event object
	/// </summary>
	// --------------------------------------------------------------------------------
	class safe_event final : public safe_object_handle
	{
	public:
		explicit safe_event(HANDLE handle) : safe_object_handle(handle)  // NOLINT(misc-misplaced-const)
		{
		}

		safe_event(const safe_event& other) = delete;

		safe_event(safe_event&& other) noexcept
			: safe_object_handle{std::move(other)}
		{
		}

		safe_event& operator=(const safe_event& other) = delete;

		safe_event& operator=(safe_event&& other) noexcept
		{
			if (this == &other)
				return *this;
			safe_object_handle::operator =(std::move(other));
			return *this;
		}

		unsigned wait(const unsigned dw_milliseconds) const
		{
			return ::WaitForSingleObject(get(), dw_milliseconds);
		}

		bool signal() const
		{
			return ::SetEvent(get()) ? true : false;
		}

		bool reset_event() const
		{
			return ::ResetEvent(get()) ? true : false;
		}

	};
}