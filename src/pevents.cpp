/*
 * WIN32 Events for POSIX
 * Author: Mahmoud Al-Qudsi <mqudsi@neosmart.net>
 * Copyright (C) 2011 - 2022 by NeoSmart Technologies
 * SPDX-License-Identifier: MIT
 */

#include "pevents.h"
#include <cassert>
#include <atomic>
#include <memory>
#include <mutex>
#include <condition_variable>
#include <chrono>
#ifdef WFMO
#include <algorithm>
#include <deque>
#endif

namespace neosmart {
#ifdef WFMO
    // Each call to WaitForMultipleObjects initializes a neosmart_wfmo_t object which tracks
    // the progress of the caller's multi-object wait and dispatches responses accordingly.
    // One neosmart_wfmo_t struct is shared for all events in a single WFMO call
    struct neosmart_wfmo_t_
    {
        std::mutex Mutex;
        std::condition_variable CVariable;
        std::atomic<int> RefCount;
        union
        {
            int FiredEvent; // WFSO
            int EventsLeft; // WFMO
        } Status{};
        bool WaitAll{};
        std::atomic<bool> StillWaiting;

        void Destroy()
        {
            // no-op for std primitives
        }
    };
    typedef neosmart_wfmo_t_ *neosmart_wfmo_t;

    // A neosmart_wfmo_info_t object is registered with each event waited on in a WFMO
    // This reference to neosmart_wfmo_t_ is how the event knows whom to notify when triggered
    struct neosmart_wfmo_info_t_ {
        neosmart_wfmo_t Waiter;
        int WaitIndex;
    };
    typedef neosmart_wfmo_info_t_ *neosmart_wfmo_info_t;
#endif // WFMO

    // The basic event structure, passed to the caller as an opaque pointer when creating events
    struct neosmart_event_t_ {
        std::condition_variable CVariable;
        std::mutex Mutex;
        bool AutoReset{};
        std::atomic<bool> State;
#ifdef WFMO
        std::deque<neosmart_wfmo_info_t_> RegisteredWaits;
#endif
    };

#ifdef WFMO
    static bool RemoveExpiredWaitHelper(const neosmart_wfmo_info_t_ wait) {
        if (wait.Waiter->StillWaiting.load(std::memory_order_relaxed)) {
            return false;
        }

        const int ref_count = wait.Waiter->RefCount.fetch_sub(1, std::memory_order_acq_rel);
        assert(ref_count > 0);

        if (ref_count == 1) {
            wait.Waiter->Destroy();
            delete wait.Waiter;
        }
        return true;
    }
#endif // WFMO

    neosmart_event_t CreateEvent(const bool manualReset, const bool initialState) {
        const auto event = new neosmart_event_t_;

        event->AutoReset = !manualReset;
        // memory_order_release: if `initialState == true`, allow a load with acquire semantics to
        // see the value.
        event->State.store(initialState, std::memory_order_release);

        return event;
    }

    static int UnlockedWaitForEvent(neosmart_event_t event, const uint64_t milliseconds, std::unique_lock<std::mutex>& lock) {
        int result = 0;
        // memory_order_relaxed: `State` is only set to true with the mutex held, and we require
        // that this function only be called after the mutex is obtained.
        if (!event->State.load(std::memory_order_relaxed)) {
            // Zero-timeout event state check optimization
            if (milliseconds == 0) {
                return WAIT_TIMEOUT;
            }

            if (milliseconds != WAIT_INFINITE) {
                const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(milliseconds);
                while (!event->State.load(std::memory_order_relaxed)) {
                    if (event->CVariable.wait_until(lock, deadline) == std::cv_status::timeout) {
                        result = WAIT_TIMEOUT;
                        break;
                    }
                }
            } else {
                while (!event->State.load(std::memory_order_relaxed)) {
                    event->CVariable.wait(lock);
                }
            }
        } else if (event->AutoReset) {
            // It's an auto-reset event that's currently available;
            // we need to stop anyone else from using it
            result = 0;
        }
        else {
            // We're trying to obtain a manual reset event with a signaled state; don't do anything
        }

        if (result == 0 && event->AutoReset) {
            // We've only accquired the event if the wait succeeded
            // memory_order_relaxed: we never act on `State == true` without fully synchronizing
            // or grabbing the mutex, so it's OK to use relaxed semantics here.
            event->State.store(false, std::memory_order_relaxed);
        }

        return result;
    }

    int WaitForEvent(neosmart_event_t event, uint64_t milliseconds) {
        // Optimization: bypass acquiring the event lock if the state atomic is unavailable.
        // memory_order_relaxed: This is just an optimization, it's OK to be biased towards a stale
        // value here, and preferable to synchronizing CPU caches to get a more accurate result.
        if (milliseconds == 0 && !event->State.load(std::memory_order_relaxed)) {
            return WAIT_TIMEOUT;
        }
        // Optimization: early return in case of success for manual reset events only.
        if (!event->AutoReset && event->State.load(std::memory_order_relaxed)) {
            // A memory barrier is required here. This is still cheaper than a syscall.
            // See https://github.com/neosmart/pevents/issues/18
            if (event->State.load(std::memory_order_acquire)) {
                return 0;
            }
        }

        std::unique_lock<std::mutex> lock(event->Mutex);
        const int result = UnlockedWaitForEvent(event, milliseconds, lock);
        return result;
    }

#ifdef WFMO
    int WaitForMultipleEvents(neosmart_event_t *events, const int count, const bool waitAll,
                              const uint64_t milliseconds) {
        int unused;
        return WaitForMultipleEvents(events, count, waitAll, milliseconds, unused);
    }

    int WaitForMultipleEvents(neosmart_event_t *events, const int count, const bool waitAll,
                              const uint64_t milliseconds, int &waitIndex) {
        const neosmart_wfmo_t wfmo = new neosmart_wfmo_t_;

        int result = 0;
        const int tempResult = 0; // placeholder for asserts
        (void)tempResult;

        neosmart_wfmo_info_t_ waitInfo;
        waitInfo.Waiter = wfmo;
        waitInfo.WaitIndex = -1;

        if (waitAll) {
            wfmo->Status.EventsLeft = count;
        } else {
            wfmo->Status.FiredEvent = -1;
        }

        wfmo->WaitAll = waitAll;
        wfmo->StillWaiting.store(true, std::memory_order_release);
        // memory_order_release: this is the initial value other threads should see
        wfmo->RefCount.store(1 + count, std::memory_order_release);
        // Separately keep track of how many refs to decrement after the initialization loop, to
        // avoid repeatedly clearing the cache line.
        int skipped_refs = 0;

        std::unique_lock<std::mutex> wfmo_lock(wfmo->Mutex);

        bool done = false;
        waitIndex = -1;

        for (int i = 0; i < count; ++i) {
            waitInfo.WaitIndex = i;

            // Skip obtaining the mutex for manual reset events. This requires a memory barrier to
            // ensure correctness.
            bool skipLock = false;
            if (!events[i]->AutoReset) {
                if (events[i]->State.load(std::memory_order_relaxed) &&
                    events[i]->State.load(std::memory_order_acquire)) {
                    skipLock = true;
                }
            }

            if (skipLock) {
                // Manual-reset event observed signaled without locking.
                if (waitAll) {
                    ++skipped_refs;
                    --wfmo->Status.EventsLeft;
                    assert(wfmo->Status.EventsLeft >= 0);
                } else {
                    skipped_refs += (count - i);
                    wfmo->Status.FiredEvent = i;
                    waitIndex = i;
                    done = true;
                    break;
                }
                continue;
            }

            // Lock to safely inspect/modify state and to register waits
            events[i]->Mutex.lock();

            // Before adding this wait to the list of registered waits, clean up expired waits.
            events[i]->RegisteredWaits.erase(std::remove_if(events[i]->RegisteredWaits.begin(),
                                                            events[i]->RegisteredWaits.end(),
                                                            RemoveExpiredWaitHelper),
                                             events[i]->RegisteredWaits.end());

            const bool signaled_now = events[i]->State.load(std::memory_order_relaxed);
            if (!signaled_now) {
                // Not signaled, register this WFMO waiter and continue
                events[i]->RegisteredWaits.push_back(waitInfo);
                events[i]->Mutex.unlock();
                continue;
            }

            // Signaled: for auto-reset, consume it under the lock; for manual-reset, nothing to do
            if (events[i]->AutoReset) {
                events[i]->State.store(false, std::memory_order_relaxed);
            }
            events[i]->Mutex.unlock();

            if (waitAll) {
                ++skipped_refs;
                --wfmo->Status.EventsLeft;
                assert(wfmo->Status.EventsLeft >= 0);
            } else {
                skipped_refs += (count - i);
                wfmo->Status.FiredEvent = i;
                waitIndex = i;
                done = true;
                break;
            }
        }

        // We set the `done` flag above in case of WaitAny and at least one event was set.
        // But we need to check again here if we were doing a WaitAll or else we'll incorrectly
        // return WAIT_TIMEOUT.
        if (waitAll && wfmo->Status.EventsLeft == 0) {
            done = true;
        }

        auto deadline = std::chrono::steady_clock::time_point::max();
        if (!done) {
            if (milliseconds == 0) {
                result = WAIT_TIMEOUT;
                done = true;
            } else if (milliseconds != WAIT_INFINITE) {
                deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(milliseconds);
            }
        }

        while (!done) {
            // One (or more) of the events we're monitoring has been triggered?

            // If we're waiting for all events, assume we're done and check if there's an event that
            // hasn't fired But if we're waiting for just one event, assume we're not done until we
            // find a fired event
            done = (waitAll && wfmo->Status.EventsLeft == 0) ||
                   (!waitAll && wfmo->Status.FiredEvent != -1);

            if (!done) {
                if (milliseconds != WAIT_INFINITE) {
                    if (wfmo->CVariable.wait_until(wfmo_lock, deadline) == std::cv_status::timeout) {
                        result = WAIT_TIMEOUT;
                        break;
                    }
                } else {
                    wfmo->CVariable.wait(wfmo_lock);
                }
            }
        }

        waitIndex = wfmo->Status.FiredEvent;
        // memory_order_relaxed: this is only checked outside the mutex to determine if waiting has
        // terminated meaning it's safe to decrement the ref count. If it's true (which we write
        // with release semantics), then the mutex is always entered.
        wfmo->StillWaiting.store(false, std::memory_order_relaxed);

        wfmo_lock.unlock();

        // memory_order_seq_cst: Ensure this is run after the wfmo mutex is unlocked
        const int ref_count = wfmo->RefCount.fetch_sub(1 + skipped_refs, std::memory_order_seq_cst);
        assert(ref_count > 0);
        if (ref_count == 1 + skipped_refs) {
            wfmo->Destroy();
            delete wfmo;
        }

        return result;
    }
#endif // WFMO

    int DestroyEvent(const neosmart_event_t event) {
#ifdef WFMO
        {
            std::lock_guard<std::mutex> lock(event->Mutex);
            event->RegisteredWaits.erase(std::remove_if(event->RegisteredWaits.begin(),
                                                        event->RegisteredWaits.end(),
                                                        RemoveExpiredWaitHelper),
                                         event->RegisteredWaits.end());
        }
#endif
        delete event;
        return 0;
    }

    int SetEvent(neosmart_event_t event) {
        std::unique_lock<std::mutex> ev_lock(event->Mutex);

        // Depending on the event type, we either trigger everyone or only one
        if (event->AutoReset) {
#ifdef WFMO
            while (!event->RegisteredWaits.empty()) {
                const neosmart_wfmo_info_t i = &event->RegisteredWaits.front();

                // memory_order_relaxed: this is just an optimization to see if it is OK to skip
                // this waiter, and if it's observed to be false then it's OK to bypass the mutex at
                // that point.
                if (!i->Waiter->StillWaiting.load(std::memory_order_relaxed)) {
                    const int ref_count = i->Waiter->RefCount.fetch_sub(1, std::memory_order_acq_rel);
                    assert(ref_count > 0);
                    if (ref_count == 1) {
                        i->Waiter->Destroy();
                        delete i->Waiter;
                    }

                    event->RegisteredWaits.pop_front();
                    continue;
                }

                std::unique_lock<std::mutex> waiter_lock(i->Waiter->Mutex);

                // We have to check `Waiter->StillWaiting` twice, once before locking as an
                // optimization to bypass the mutex altogether, and then again after locking the
                // WFMO mutex because we could have !waitAll and another event could have ended the
                // wait, in which case we must not unlock the same waiter or else a SetEvent() call
                // on an auto-reset event may end up with a lost wakeup.
                if (!i->Waiter->StillWaiting.load(std::memory_order_relaxed)) {
                    waiter_lock.unlock();

                    // memory_order_seq_cst: Ensure this is run after the wfmo mutex is unlocked
                    const int ref_count = i->Waiter->RefCount.fetch_sub(1, std::memory_order_seq_cst);
                    assert(ref_count > 0);
                    if (ref_count == 1) {
                        i->Waiter->Destroy();
                        delete i->Waiter;
                    }

                    event->RegisteredWaits.pop_front();
                    continue;
                }

                if (i->Waiter->WaitAll) {
                    --i->Waiter->Status.EventsLeft;
                    assert(i->Waiter->Status.EventsLeft >= 0);
                    // We technically should do i->Waiter->StillWaiting = Waiter->Status.EventsLeft
                    // != 0 but the only time it'll be equal to zero is if we're the last event, so
                    // no one else will be checking the StillWaiting flag. We're good to go without
                    // it.
                } else {
                    i->Waiter->Status.FiredEvent = i->WaitIndex;
                    // memory_order_relaxed: The flip to false is only lazily observed as an
                    // optimization to bypass the mutex for cleanup.
                    i->Waiter->StillWaiting.store(false, std::memory_order_relaxed);
                }

                waiter_lock.unlock();

                i->Waiter->CVariable.notify_one();

                // memory_order_seq_cst: Ensure this is run after the wfmo mutex is unlocked
                const int ref_count = i->Waiter->RefCount.fetch_sub(1, std::memory_order_seq_cst);
                assert(ref_count > 0);
                if (ref_count == 1) {
                    i->Waiter->Destroy();
                    delete i->Waiter;
                }

                event->RegisteredWaits.pop_front();

                ev_lock.unlock();

                return 0;
            }
#endif // WFMO
            // memory_order_release: this is the synchronization point for any threads spin-waiting
            // for the event to become available.
            event->State.store(true, std::memory_order_release);

            ev_lock.unlock();

            event->CVariable.notify_one();

            return 0;
        } else { // this is a manual reset event
            // memory_order_release: this is the synchronization point for any threads spin-waiting
            // for the event to become available.
            event->State.store(true, std::memory_order_release);
#ifdef WFMO
            for (size_t i = 0; i < event->RegisteredWaits.size(); ++i) {
                const neosmart_wfmo_info_t info = &event->RegisteredWaits[i];

                // memory_order_relaxed: this is just an optimization to see if it is OK to skip
                // this waiter, and if it's observed to be false then it's OK to bypass the mutex at
                // that point.
                if (!info->Waiter->StillWaiting.load(std::memory_order_relaxed)) {
                    const int ref_count = info->Waiter->RefCount.fetch_sub(1, std::memory_order_acq_rel);
                    if (ref_count == 1) {
                        info->Waiter->Destroy();
                        delete info->Waiter;
                    }
                    continue;
                }

                std::unique_lock<std::mutex> waiter_lock(info->Waiter->Mutex);

                // Waiter->StillWaiting may have become true by now, but we're just going to pretend
                // it hasn't. So long as we hold a reference to the WFMO, this is safe since manual
                // reset events are not one-time use.

                if (info->Waiter->WaitAll) {
                    --info->Waiter->Status.EventsLeft;
                    assert(info->Waiter->Status.EventsLeft >= 0);
                    // We technically should do i->Waiter->StillWaiting = Waiter->Status.EventsLeft
                    // != 0 but the only time it'll be equal to zero is if we're the last event, so
                    // no one else will be checking the StillWaiting flag. We're good to go without
                    // it.
                } else {
                    info->Waiter->Status.FiredEvent = info->WaitIndex;
                    // memory_order_relaxed: The flip to false is only lazily observed as an
                    // optimization to bypass the mutex for cleanup.
                    info->Waiter->StillWaiting.store(false, std::memory_order_relaxed);
                }

                waiter_lock.unlock();

                info->Waiter->CVariable.notify_one();

                // memory_order_seq_cst: Ensure this is run after the wfmo mutex is unlocked
                const int ref_count = info->Waiter->RefCount.fetch_sub(1, std::memory_order_seq_cst);
                assert(ref_count > 0);
                if (ref_count == 1) {
                    info->Waiter->Destroy();
                    delete info->Waiter;
                }
                continue;
            }
            event->RegisteredWaits.clear();
#endif // WFMO
            ev_lock.unlock();

            event->CVariable.notify_all();
        }

        return 0;
    }

    int ResetEvent(neosmart_event_t event) {
        // memory_order_relaxed and no mutex: there can't be any guarantees about concurrent calls
        // to either of WFMO()/SetEvent() and ResetEvent() because they're racy by nature. Only the
        // behavior of concurrent WFMO() and SetEvent() calls is strongly defined.
        event->State.store(false, std::memory_order_relaxed);
        return 0;
    }

#ifdef PULSE
    int PulseEvent(neosmart_event_t event) {
        // This may look like it's a horribly inefficient kludge with the sole intention of reducing
        // code duplication, but in reality this is what any PulseEvent() implementation must look
        // like. The only overhead (function calls aside, which your compiler will likely optimize
        // away, anyway), is if only WFMO auto-reset waits are active there will be overhead to
        // unnecessarily obtain the event mutex for ResetEvent() after. In all other cases (being no
        // pending waits, WFMO manual-reset waits, or any WFSO waits), the event mutex must first be
        // released for the waiting thread to resume action prior to locking the mutex again in
        // order to set the event state to unsignaled, or else the waiting threads will loop back
        // into a wait (due to checks for spurious CVariable wakeups).

        int result = SetEvent(event);
        assert(result == 0);
        result = ResetEvent(event);
        assert(result == 0);

        return 0;
    }
#endif
} // namespace neosmart

