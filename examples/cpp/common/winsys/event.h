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