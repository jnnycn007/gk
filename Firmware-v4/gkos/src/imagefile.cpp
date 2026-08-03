#include "imagefile.h"

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
        // TODO
    }

    return 0;
}
