#include "thread.h"
#include "memblk.h"
#include "mpuregions.h"

#include <cstring>

#include "scheduler.h"
#include "cache.h"
#include "gk_conf.h"
#include "clocks.h"
#include "ossharedmem.h"
#include "process.h"
#include "cleanup.h"

#include <sys/reent.h>

extern Thread dt;

Thread::Thread(Process &owning_process) : p(owning_process) {}

void Thread::Cleanup(void *tretval)
{
    {
        CriticalGuard cg(sl);
        for_deletion = true;
    }

    if(is_privileged)
    {
        // execute any cleanup handlers - may task switch here
        for(auto iter = cleanup_list.rbegin(); iter != cleanup_list.rend(); iter++)
        {
            if(iter->routine)
            {
                iter->routine(iter->arg);
            }
        }
        cleanup_list.clear();
    }

    {
        CriticalGuard cg(sl);
            
        retval = tretval;

        // signal any thread waiting on a join
        if(join_thread)
        {
            if(join_thread_retval)
                *join_thread_retval = tretval;
            join_thread->ss_p.ival1 = 0;
            join_thread->ss.Signal();
            join_thread->blocking_on = nullptr;
            join_thread->is_blocking = false;
            join_thread->block_until = kernel_time();

            join_thread = nullptr;
        }

        // remove us from the process' thread list
        {
            CriticalGuard cg2;
            auto iter = p.threads.begin();
            while(iter != p.threads.end())
            {
                if(*iter == this)
                    iter = p.threads.erase(iter);
                else
                    iter++;
            }
        }

        CleanupQueue.Push({ .is_thread = true, .t = this });
    }
}

void thread_cleanup(void *tretval)   // both return value and first param are in R0, so valid
{
    auto t = GetCurrentThreadForCore();
    t->Cleanup(tretval);
    while(true)
    {
        Yield();
    }
}

Thread *Thread::Create(std::string name,
            threadstart_t func,
            void *p,
            bool is_priv, int priority,
            Process &owning_process,
            CPUAffinity affinity,
            MemRegion stackblk,
            void *p_r1)
{
    auto t = new Thread(owning_process);
    if(!t) return nullptr;
    
    memset(&t->tss, 0, sizeof(thread_saved_state));

    t->base_priority = priority;
    t->is_privileged = is_priv;
    t->name = name;

    t->tss.lr = 0xfffffffdUL;               // return to thread mode, normal frame, use PSP
    t->tss.control = is_priv ? 2UL : 3UL;   // bit0 = !privilege, bit1 = use PSP

    _REENT_INIT_PTR(&t->tss.newlib_reent);

    /* Create TLS, if any */
    if(owning_process.has_tls)
    {
        t->mr_tls = InvalidMemregion();
        if(affinity == CPUAffinity::M4Only || affinity == CPUAffinity::PreferM4)
            t->mr_tls = memblk_allocate(owning_process.tls_memsz + 8, MemRegionType::SRAM, "tls");
        if(!t->mr_tls.valid)
            t->mr_tls = memblk_allocate(owning_process.tls_memsz + 8, MemRegionType::AXISRAM, "tls");
        if(!t->mr_tls.valid)
        {
            t->mr_tls = memblk_allocate(owning_process.tls_memsz + 8, MemRegionType::SDRAM, "tls");
        }
        if(!t->mr_tls.valid)
        {
            return nullptr;
        }

        // initialize TLS segment
        {
            //SharedMemoryGuard smg_write((void *)t->mr_tls.address, owning_process.tls_memsz, false, true);
            //SharedMemoryGuard smg_read((void *)owning_process.tls_base, owning_process.tls_filsz, true, false);
            // ARM32 has TLS segments starting 8 bytes after tp.  We can use these for other things
            *(volatile uint32_t *)(t->mr_tls.address + 0) = (uint32_t)owning_process.pid;   // proc ID
            *(volatile uint32_t *)(t->mr_tls.address + 4) = (uint32_t)(uintptr_t)t;         // thread ID
            memcpy((void *)(t->mr_tls.address + 8), (void *)owning_process.tls_base, owning_process.tls_filsz);
            memset((void *)(t->mr_tls.address + 8 + owning_process.tls_filsz), 0,
                owning_process.tls_memsz - owning_process.tls_filsz);
        }
    }

    /* Create stack frame */
    if(stackblk.valid)
    {
        t->stack = stackblk;
    }
    else
    {
        t->stack = memblk_allocate_for_stack(4096U, affinity, name + " stack", owning_process.stack_preference);
    }
#if !GK_DUAL_CORE_AMP && !GK_DUAL_CORE
    // we keep PreferM4 as a separate option until now to allow better stack placement for low priority tasks
    affinity = CPUAffinity::M7Only;
#endif
    t->tss.affinity = affinity;

    if(!t->stack.valid)
        return nullptr;

    /* Basic stack frame layout is
        top of stack --
            xPSR
            Return address
            LR
            R12
            R3
            R2
            R1
            R0
        bottom of stack --
    */
    auto top_stack = t->stack.length / 4;
    if(t->stack.length > 128)
    {
        // add stack guards
        top_stack -= t->stack.length / 8 / 4;
    }
    auto stack = reinterpret_cast<uint32_t *>(t->stack.address);

    auto cleanup_func = is_priv ? reinterpret_cast<uint32_t>(thread_cleanup) : owning_process.thread_finalizer;
    
    {
        //SharedMemoryGuard sg((const void *)(t->stack.address + t->stack.length - 8*4),
        //    t->stack.is_cacheable() ? 8*4 : 0, false, true);
        stack[--top_stack] = 1UL << 24; // THUMB mode
        stack[--top_stack] = reinterpret_cast<uint32_t>(func) | 1UL;
        stack[--top_stack] = cleanup_func | 1UL;
        stack[--top_stack] = 0UL;
        stack[--top_stack] = 0UL;
        stack[--top_stack] = 0UL;
        stack[--top_stack] = reinterpret_cast<uint32_t>(p_r1);
        stack[--top_stack] = reinterpret_cast<uint32_t>(p);
    }

    //t->tss.psp = t->stack.address + t->stack.length;
    t->tss.psp = reinterpret_cast<uint32_t>(&stack[top_stack]);
    
    /* Create mpu regions */
    memcpy(t->tss.mpuss, owning_process.p_mpu, sizeof(mpu_default));
    if(owning_process.has_tls && owning_process.p_mpu_tls_id < 16)
    {
        Process::mmap_region mmr_tls { .mr = t->mr_tls, .fd = -1, .is_read = true, .is_write = true, .is_exec = false, .is_sync = false };
        t->tss.mpuss[owning_process.p_mpu_tls_id] = mmr_tls.to_mpu(owning_process.p_mpu_tls_id);
    }
    owning_process.AddMPURegion({ .mr = t->stack, .fd = -1, .is_read = true, .is_write = true, .is_exec = false, .is_sync = false,
        .is_stack = true, .is_priv = is_priv });

    {
        CriticalGuard cg;
        owning_process.threads.push_back(t);
    }
    
    owning_process.UpdateMPURegionsForThreads();

    return t;
}

INTFLASH_FUNCTION Thread *GetCurrentThreadForCore(int coreid)
{
#if GK_DUAL_CORE | GK_DUAL_CORE_AMP
    if(coreid == -1)
    {
        coreid = GetCoreID();
    }
#else
    return sched.current_thread[0];
#endif

#if GK_DUAL_CORE
    {
        //CriticalGuard cg(s.current_thread[coreid].m);
        return sched.current_thread[coreid].v;  // <- should be atomic
    }
#elif GK_DUAL_CORE_AMP
    return scheds[coreid].current_thread[0].v;
#endif
}

Thread *GetNextThreadForCore(int coreid)
{
#if GK_DUAL_CORE | GK_DUAL_CORE_AMP
    if(coreid == -1)
    {
        coreid = GetCoreID();
    }
#else
    return sched.GetNextThread(0);
#endif

#if GK_DUAL_CORE
    return sched.GetNextThread(coreid);
#elif GK_DUAL_CORE_AMP
    return scheds[coreid].GetNextThread(coreid);
#endif
}

int GetCoreID()
{
#if GK_DUAL_CORE | GK_DUAL_CORE_AMP
    return (*( ( volatile uint32_t * ) 0xE000ed00 ) & 0xfff0UL) == 0xc240 ? 1 : 0;
#else
    return 0;
#endif
}

void SetNextThreadForCore(Thread *t, int coreid)
{
    [[maybe_unused]] bool flush_cache = false;

#if GK_DUAL_CORE | GK_DUAL_CORE_AMP
    if(coreid == -1)
    {
        coreid = GetCoreID();
    }
#else
    coreid = 0;
#endif

    {
        CriticalGuard cg;

        if(current_thread(coreid))
        {
            CriticalGuard cg2;
            current_thread(coreid)->tss.chosen_for_core = 0;
            current_thread(coreid)->tss.running_on_core = 0;
            current_thread(coreid)->total_us_time += clock_cur_us() -
                current_thread(coreid)->cur_timeslice_start;
            if(current_thread(coreid) == &dt)
            {
                flush_cache = true;
            }
        }

        {
            CriticalGuard cg2;
            t->tss.chosen_for_core = 0;
            t->tss.running_on_core = coreid + 1;
            t->cur_timeslice_start = clock_cur_us();

            if(t->get_is_blocking())
            {
                while(true);
            }
        }

        current_thread(coreid) = t;

        extern uint32_t _tls_pointers[];
        _tls_pointers[coreid] = t->mr_tls.address;
    }
}

std::map<uint32_t, Process::mmap_region>::iterator Process::get_mmap_region(uint32_t addr, uint32_t len)
{
    // lookup on addr but also has to match length (we can't delete bits of blocks)
    auto iter = mmap_regions.find(addr);
    if(iter != mmap_regions.end() && iter->second.mr.length == len)
    {
        return iter;
    }
    return mmap_regions.end();
}

bool Thread::addr_is_valid(const void *addr, size_t len, bool for_write) const
{
    /* just check against the valid mpu regions of this thread.
        This function is used by syscalls, gpu, ext4 etc which
        operate with the default background map, so they will
        allow memory access outside of the areas protected by
        the MPU, so do a check here instead.
    */

    if(is_privileged)
        return true;

    auto start = (uint32_t)(uintptr_t)addr;
    auto end = start + len;
    
    for(int i = 0; i < 16; i++)
    {
        const auto &cmpu = tss.mpuss[i];
        if(cmpu.is_enabled())
        {
            auto up_access = cmpu.unpriv_access();
            if(up_access == NoAccess)
                continue;
            if(for_write && up_access != RW)
                continue;

            auto c_start = cmpu.base_addr();
            auto c_len = cmpu.length();

            // check SRD bits
            auto srd = (cmpu.rasr >> 8) & 0xffU;

            if(srd != 0)
            {
                if(srd != 0x81U)
                {
                    BKPT_IF_DEBUGGER();     // not supported
                    c_len = 0;
                }

                c_start += c_len / 8;
                c_len -= c_len / 4;
            }

            auto c_end = c_start + c_len;

            if(start >= c_start && end <= c_end)
                return true;
        }
    }

    klog("kernel: userspace (%s - %s) invalid %s access at %08x to %08x\n",
        name.c_str(), p.name.c_str(),
        for_write ? "write" : "read",
        start, end);

    return false;
}
