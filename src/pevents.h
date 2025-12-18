/*
 * WIN32 Events for POSIX
 * Author: Mahmoud Al-Qudsi <mqudsi@neosmart.net>
 * Copyright (C) 2011 - 2022 by NeoSmart Technologies
 * SPDX-License-Identifier: MIT
 */

#pragma once

#if defined(_WIN32) && !defined(CreateEvent)
#include <Windows.h>
#undef max
#undef min
#endif
#ifndef WAIT_TIMEOUT
#include <cerrno>
#define WAIT_TIMEOUT ETIMEDOUT
#endif

#include <cstdint>

namespace neosmart {
    // Type declarations
    struct neosmart_event_t_;
    typedef neosmart_event_t_ *neosmart_event_t;

    // Constant declarations
    constexpr uint64_t WAIT_INFINITE = ~static_cast<uint64_t>(0);

    // Function declarations
    neosmart_event_t CreateEvent(bool manualReset = false, bool initialState = false);
    int DestroyEvent(neosmart_event_t event);
    int WaitForEvent(neosmart_event_t event, uint64_t milliseconds = WAIT_INFINITE);
    int SetEvent(neosmart_event_t event);
    int ResetEvent(neosmart_event_t event);
#ifdef WFMO
    int WaitForMultipleEvents(neosmart_event_t *events, int count, bool waitAll,
                              uint64_t milliseconds);
    int WaitForMultipleEvents(neosmart_event_t *events, int count, bool waitAll,
                              uint64_t milliseconds, int &index);
#endif
#ifdef PULSE
    int PulseEvent(neosmart_event_t event);
#endif
} // namespace neosmart
