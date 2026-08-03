#include "imagefile.h"
#include "process.h"
#include "thread.h"
#include "syscalls_int.h"

ImageFile::ImageFile(const std::string &_path, int _dl_id) 
{
    path = _path;
    dl_id = _dl_id;
    type = FT_ImageFile;
}

void ImageFile::DlClose()
{
    type = FT_ClosedImageFile;
}

int ImageFile::GetDlId() const
{
    return dl_id;
}

int ImageFile::Close(int *_errno)
{
    if(type == FT_ClosedImageFile)
    {
        klog("ImageFile: closing dl_id %d\n", dl_id);

        auto p = GetCurrentProcessForCore();
        if(p)
        {
            MutexGuard mg(p->imgs.m);

            if(dl_id >= 0 && (unsigned)dl_id < p->imgs.imgs.size())
            {
                auto &img = p->imgs.imgs[dl_id];
                if(img.fd)
                {
                    /* close the entry without deleting (imgs is a vector so we don't
                        want to affect other offsets by erase()ing it) */
                    
                    for(const auto &mb : *img.mregs)
                    {
                        syscall_memdealloc(mb.length, (const void *)mb.base, _errno);
                    }
                    img.baseaddr = nullptr;
                    img.global = true;
                    img.handle.reset();
                    img.img = nullptr;
                    img.mregs->clear();
                    img.fd = nullptr;
                }
            }
        }
    }

    return 0;
}
