#include "elf.h"
#include "process.h"
#include "syscalls_int.h"
#include "vmem.h"
#include "pmem.h"

int elf_load_fildes(int fd, PProcess p, Thread::threadstart_t *epoint, bool global)
{
    if(fd < 0)
        return -1;

    PFile pf;
    {
        CriticalGuard cg(p->open_files.sl);
        if((size_t)fd >= p->open_files.f.size())
        {
            return -1;
        }
        pf = p->open_files.f[fd];
    }
    if(!pf)
    {
        return -1;
    }
    // we use syscall_read to write to kernel heap structures here
    ThreadPrivilegeEscalationGuard tpeg;
        
    // check header for sanity
    Elf64_Ehdr hdr;
    deferred_call(syscall_lseek, fd, 0, SEEK_SET);
    auto [ bret, berrno ] = deferred_call(syscall_read, fd, (char *)&hdr, sizeof(hdr));
    if(bret != sizeof(hdr))
    {
        klog("elf_load_fildes: failed to read header: %d, %d\n", bret, berrno);
        return -1;
    }

    if(hdr.e_ident[0] != '\x7f' ||
        hdr.e_ident[1] != 'E' ||
        hdr.e_ident[2] != 'L' ||
        hdr.e_ident[3] != 'F')
    {
        klog("elf: ident fail %02x %02x %02x %02x\n",
            hdr.e_ident[0], hdr.e_ident[1], hdr.e_ident[2], hdr.e_ident[3]);
        return -1;
    }
    if(hdr.e_ident[EI_CLASS] != ELFCLASS64)
    {
        klog("elf: class fail %u\n", hdr.e_ident[EI_CLASS]);
        return -1;
    }
    if(hdr.e_ident[EI_DATA] != ELFDATA2LSB)
    {
        klog("elf: data type fail %u\n", hdr.e_ident[EI_DATA]);
        return -1;
    }
    if(epoint)
    {
        if(hdr.e_type != ET_EXEC)
        {
            klog("elf: type fail %u\n", hdr.e_type);
            return -1;
        }
    }
    else
    {
        if(hdr.e_type != ET_EXEC && hdr.e_type != ET_DYN && hdr.e_type != ET_REL)
        {
            klog("elf: type fail %u\n", hdr.e_type);
            return -1;
        }
    }
    if(hdr.e_machine != EM_AARCH64)
    {
        klog("elf: machine type fail %u\n", hdr.e_machine);
        return -1;
    }

    if(hdr.e_phentsize < sizeof(Elf64_Phdr))
    {
        klog("elf: phentsize too small: %u\n", hdr.e_phentsize);
        return -1;
    }

    /* For ET_DYN and ET_REL images we allocate a chunk big enough for the
        entire loaded image, get its base address, then immediately free it
        We then use its base address in calls to AllocFixed().
        
        Therefore, ensure nothing else allocates memory in between these
         calls */
    MutexGuard mg_vblock(p->user_mem->vblocks.m);
    uint64_t baseaddr = 0;

    {
        Process::images_t::img img;
        img.baseaddr = (void *)0;
        img.fd = fd;
        img.path = pf->path;
        img.img = (void *)0;
        img.global = global;

        int _errno = 0;
        auto flen = pf->Flen(&_errno);

        /* Load the entire image somewhere so userspace can access the elf headers */
        {
            auto pmb = MemBlock::FileBackedReadOnlyMemory(0, (flen + (VBLOCK_64k - 1)) & ~VBLOCK_64k, pf, 0,
                flen, true, false);
            MutexGuard cg(p->user_mem->m);
            auto vb = p->user_mem->vblocks.AllocAny(pmb, false);
            if(!vb.valid)
            {
                klog("elf: unable to allocate vblock of length %u\n", pmb.b.length);
            }
            img.img = (void *)vb.base;
        }

        if(hdr.e_type == ET_DYN || hdr.e_type == ET_REL)
        {
            // need to find a free memory region for use

            // first, get the highest address of a load or tls section
            uint64_t max_addr = 0;

            for(auto i = 0U; i < hdr.e_phnum; i++)
            {
                Elf64_Phdr phdr;
                deferred_call(syscall_lseek, fd, hdr.e_phoff + hdr.e_phentsize * i, SEEK_SET);
                std::tie(bret, berrno) = deferred_call(syscall_read, fd, (char *)&phdr, sizeof(Elf64_Phdr));
                if(bret != sizeof(Elf64_Phdr))
                {
                    klog("elf_load_filedes: failed to load phdr: %d, %d\n", bret, berrno);
                    return -1;
                }
                if(phdr.p_type == PT_LOAD || phdr.p_type == PT_TLS)
                {
                    auto f_start = phdr.p_offset & ~(PAGE_SIZE - 1);
                    auto f_zeroend = (phdr.p_offset + phdr.p_memsz + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1);
                    auto mem_start = phdr.p_vaddr & ~(PAGE_SIZE - 1);
                    auto memsz = f_zeroend - f_start;

                    auto mem_end = mem_start + memsz;
                    if(mem_end > max_addr)
                        max_addr = mem_end;
                }
            }

            auto pmb_all_load = MemBlock::ZeroBackedReadOnlyMemory(0, max_addr, false, false);
            auto vb_all_load = p->user_mem->vblocks.AllocAny(pmb_all_load, false);
            if(!vb_all_load.valid)
            {
                klog("elf: unable to allocate vblock of length %u for all load segments\n",
                    max_addr);
                return -1;
            }

            baseaddr = vb_all_load.data_start();
            img.baseaddr = (void *)(uintptr_t)baseaddr;

            p->user_mem->vblocks.Dealloc(vb_all_load);
        }

        klog("elf: add process image: %s, fd: %d, baseaddr: %p, elf: %p, elf_len: %u\n", 
            img.path.c_str(), img.fd, img.baseaddr, img.img, flen);

        {
            CriticalGuard cg(p->imgs.sl);
            p->imgs.imgs.push_back(img);
        }
    }

    // load the appropriate phdrs
    for(auto i = 0U; i < hdr.e_phnum; i++)
    {
        Elf64_Phdr phdr;
        deferred_call(syscall_lseek, fd, hdr.e_phoff + hdr.e_phentsize * i, SEEK_SET);
        std::tie(bret, berrno) = deferred_call(syscall_read, fd, (char *)&phdr, sizeof(Elf64_Phdr));
        if(bret != sizeof(Elf64_Phdr))
        {
            klog("elf_load_filedes: failed to load phdr: %d, %d\n", bret, berrno);
            return -1;
        }
        if(phdr.p_type == PT_LOAD || phdr.p_type == PT_TLS)
        {
            bool writeable = (phdr.p_flags & PF_W) != 0;
            bool exec = (phdr.p_flags & PF_X) != 0;

            auto f_start = phdr.p_offset & ~(PAGE_SIZE - 1);
            auto f_dataend = phdr.p_offset + phdr.p_filesz;
            auto f_zeroend = (phdr.p_offset + phdr.p_memsz + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1);
            auto mem_start = phdr.p_vaddr & ~(PAGE_SIZE - 1);
            auto filesz = f_dataend - f_start;
            auto memsz = f_zeroend - f_start;

            mem_start += baseaddr;

            bool is_tls = phdr.p_type == PT_TLS;
            if(is_tls)
            {
                if(p->vb_tls.valid)
                {
                    klog("elf: too many PT_TLS sections in file\n");
                    return -1;
                }

                MutexGuard mg(p->user_mem->m);
                p->vb_tls = p->user_mem->vblocks.AllocAny(
                    MemBlock::FileBackedReadOnlyMemory(0, phdr.p_memsz, pf, phdr.p_offset, phdr.p_filesz,
                        false, false), false);
                if(!p->vb_tls.valid)
                {
                    klog("elf: couldn't allocate vblock for PT_TLS of size %llu\n",
                        phdr.p_memsz);
                    return -1;
                }
                p->vb_tls_data_size = phdr.p_memsz;
            }
            else if(writeable)
            {
                MutexGuard mg(p->user_mem->m);
                auto vbret = p->user_mem->vblocks.AllocFixed(
                    MemBlock::FileBackedReadWriteMemory(mem_start, memsz, pf, f_start,
                        filesz, true, exec));
                if(!vbret.valid)
                {
                    klog("elf: couldn't allocate block at %p - %p\n", (void *)mem_start,
                        (void *)(mem_start + memsz));
                    return -1;
                }
            }
            else
            {
                MutexGuard mg(p->user_mem->m);
                auto vbret = p->user_mem->vblocks.AllocFixed(
                    MemBlock::FileBackedReadOnlyMemory(mem_start, memsz, pf, f_start,
                        filesz, true, exec));
                if(!vbret.valid)
                {
                    klog("elf: couldn't allocate block at %p - %p\n", (void *)mem_start,
                        (void *)(mem_start + memsz));
                    return -1;
                }
            }
        }
    }

    {
        MutexGuard mg(p->user_mem->m);
        klog("elf: userspace map:\n");
        p->user_mem->vblocks.Traverse([](MemBlock &mb)
        {
            klog("mmap: %p - %p, %s%s%s%s %llx %llx\n",
                (void *)mb.b.data_start(),
                (void *)mb.b.data_end(),
                mb.b.user ? "U" : " ",
                mb.b.write ? "W" : " ",
                mb.b.exec ? "X" : " ",
                (mb.f == nullptr) ? "" : " FILE",
                mb.foffset,
                mb.flen);
            return 0;
        });
    }

    if(epoint)
        *epoint = (Thread::threadstart_t)hdr.e_entry;
    
    return 0;
}
