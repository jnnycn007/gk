#include "syscalls_int.h"
#include "process.h"
#include "elf.h"
#include <fcntl.h>
#include "imagefile.h"

int syscall_getndl(int *_errno)
{
    auto p = GetCurrentProcessForCore();

    if(!p)
    {
        *_errno = ENOSYS;
        return -1;
    }

    CriticalGuard cg(p->imgs.sl);
    return (int)p->imgs.imgs.size();
}

int syscall_getdl(int dl_id, int *fd, char *name, size_t *namelen, void **img, void **baseaddr, int *_errno)
{
    // no longer supported
    return -1;
}

int syscall_loadimage(int fd, int global, int *_errno)
{
    // no longer supported
    return -1;
}

int syscall_dlopen(const char *path, int *dl_id, int global, int *run_init, int *_errno)
{
    PFile ret;
    auto p = GetCurrentProcessForCore();
    if(!p)
    {
        *_errno = ENOSYS;
        return -1;
    }

    /* Prevent multiple dlopen calls running concurrently - this prevents a race later
        where we do not find the path in the current image list and so create it and
        add to the list.  Potentially multiple threads could fail to find the image
        and so create multiple versions of it.
       All other concurrent access to the image array is handled through a spinlock
        instead. */
    MutexGuard(p->imgs.m);

    *_errno = 0;

    if(run_init)
        *run_init = 0;      // default is not to run init functions

    if(dl_id && *dl_id >= 0)
    {
        // if we already have an image id, just try and get it
        CriticalGuard cg(p->imgs.sl);
        if((unsigned)*dl_id < p->imgs.imgs.size())
        {
            ret = p->imgs.imgs[*dl_id].handle.lock();
            if(ret->GetType() != FT_ImageFile)
            {
                // potentially already closing
                ret = nullptr;
            }
        }
    }

    // fall through here in case dl_id fails but we still have a valid path
    //  OR, dl_id was never specified but path was    
    if(!ret && path)
    {
        int new_dl_id = -1;
        auto act_path = parse_fname(path);

        // is this image already loaded?
        {
            CriticalGuard cg(p->imgs.sl);
            for(auto idx = 0u; idx < p->imgs.imgs.size(); idx++)
            {
                auto &cimg = p->imgs.imgs[idx];
                if(cimg.fd->path == act_path)
                {
                    ret = cimg.handle.lock();
                    if(ret && ret->GetType() == FT_ImageFile)
                    {
                        new_dl_id = idx;
                        break;
                    }
                }
            }
        }

        if(!ret)
        {
            // else, try and load it
            auto img_file = OpenFile(act_path.c_str(), 0, O_RDONLY, _errno);
            if(img_file == nullptr)
            {
                return -1;
            }

            auto eret = elf_load_fildes(img_file, *p, nullptr, global != 0, &new_dl_id);
            if(eret < 0)
            {
                errno = EINVAL;
                return eret;
            }

            ret = std::make_shared<ImageFile>(act_path, new_dl_id);
            if(run_init)
                *run_init = 1;  // as this is the first load, we do need to run init
        }

        if(dl_id)
            *dl_id = new_dl_id;
    }

    // if ret is null here, all the above attempts have failed
    if(!ret)
    {
        // if no other errno has been set, then make one up
        if(*_errno == 0)
            *_errno = EINVAL;
        return -1;
    }

    // Finally, assign the image file to a fd
    CriticalGuard cg(p->open_files.sl);
    auto fd = p->open_files.get_free_fildes();
    if(fd < 0)
    {
        *_errno = EMFILE;
        ret->Close(_errno);
        ret->Close2(_errno);
        return -1;
    }
    p->open_files.f[fd] = ret;
    return fd;
}

int syscall_getdlex(int *dl_id, int fd, char *name, size_t *namelen, void **img, void **baseaddr,
    int *global, int *_errno)
{
    auto p = GetCurrentProcessForCore();
    if(!p)
    {
        *_errno = ENOSYS;
        return -1;
    }

    int act_dl_id = dl_id ? *dl_id : -1;

    if(act_dl_id < 0 && fd >= 0)
    {
        // try and get dl_id from fd
        CriticalGuard cg(p->open_files.sl);
        if((unsigned)fd < p->open_files.f.size() && p->open_files.f[fd] != nullptr &&
            p->open_files.f[fd]->GetType() == FT_ImageFile)
        {
            auto ifile = (ImageFile *)p->open_files.f[fd].get();
            act_dl_id = ifile->GetDlId();
        }
    }

    if(act_dl_id < 0)
    {
        // no valid image found
        *_errno = ENOENT;
        return -1;
    }

    if(dl_id)
        *dl_id = act_dl_id;

    CriticalGuard cg(p->imgs.sl);
    if((size_t)act_dl_id >= p->imgs.imgs.size())
    {
        *namelen = 0;
        *_errno = ENOENT;
        return -1;
    }

    const auto &dl = p->imgs.imgs[(size_t)act_dl_id];
    if(!dl.fd)
    {
        *_errno = EBADF;
        return -1;
    }
    if(img)
        *img = dl.img;
    if(baseaddr)
        *baseaddr = dl.baseaddr;
    if(global)
        *global = dl.global ? 1 : 0;

    if(name && namelen)
    {
        if(dl.fd->path.length() > (*namelen - 1))
        {
            *namelen = dl.fd->path.length() + 1;
            *_errno = EAGAIN;
            return -1;
        }

        *namelen = dl.fd->path.length() + 1;
        strcpy(name, dl.fd->path.c_str());
    }

    return 0;
}

int syscall_dlclose(int fd, int *run_fini, int *_errno)
{
    if(fd < 0)
    {
        *_errno = EBADF;
        return -1;
    }

    auto p = GetCurrentProcessForCore();
    if(!p)
    {
        *_errno = ENOSYS;
        return -1;
    }

    // default is to not run .fini
    if(run_fini)
        *run_fini = 0;

    MutexGuard mg(p->imgs.m);
    CriticalGuard cg(p->open_files.sl);
    if((unsigned)fd >= p->open_files.f.size() || !p->open_files.f[fd] || 
        p->open_files.f[fd]->GetType() != FT_ImageFile)
    {
        *_errno = EBADF;
        return -1;
    }

    // are we the last user of this file?
    if(p->open_files.f[fd].use_count() == 1)
    {
        // switch it to a ClosedImageFile
        ((ImageFile *)p->open_files.f[fd].get())->DlClose();

        // tell the user to run .fini etc
        if(run_fini)
            *run_fini = 1;
    }
    else
    {
        // not the last user - simply delete the fd
        p->open_files.f[fd].reset();
    }

    return 0;
}
