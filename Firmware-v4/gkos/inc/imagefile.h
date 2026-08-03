#ifndef IMAGEFILE_H
#define IMAGEFILE_H

#include "osfile.h"

/* This represents a userspace reference to an image file.
    The image file is linked to a member of the image array in the process
     by index.  The image array member, conversely, contains an actual
     PFile to whatever is backing the memory, a list of all vmem blocks used
     by this image as well as a weak pointer back to this file.

    The weak pointer is used in dlopen() calls to see if the image handle
     already exists.  If it does, then a copy is returned to userspace and
     userspace is told not to run the userspace .init and .init_array
     functions.

    On dlclose() of this file, the calling syscall determines (with
     process files spinlock locked) whether the use_count is 1.  If so,
     it replaces the file type with ClosedImageFile
     and tells userspace to call the .fini/.fini_array code.  Userspace
     then close()s the ClosedImageFile which causes the image array
     member to be destroyed with resultant cleanup of the vmem areas, 
     vmem_unmap and freeing of physical pages.
    If use_count() is > 1 then the file is simply closed.
*/

class ImageFile : public File
{
    protected:
        int dl_id = -1;

    public:
        ImageFile(const std::string &path, int dl_id);
        void DlClose();
        int GetDlId() const;
};

#endif
