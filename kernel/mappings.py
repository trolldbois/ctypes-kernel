import ctypes, struct, mmap, logging
# local
from haystack.memory_mapping import MemoryDumpMemoryMapping 
# TODO check ctypes_tools.bytes2array in ptrace

log = logging.getLogger('mappings')


class MemdumpFileMemoryMapping(MemoryDumpMemoryMapping):
    """ A memoryMapping wrapper around a memory file dump"""
    def __init__(self, memdump, start, end, dtb):
        self._process = None
        self.start = start
        self.end = end
        self.permissions = 'rwx-'
        self.offset = 0x0
        self.major_device = 0x0
        self.minor_device = 0x0
        self.inode = 0x0
        self.pathname = 'MEMORYDUMP'
        self.local_mmap = mmap.mmap(memdump.fileno(), end-start, access=mmap.ACCESS_READ)
        ###
        print 'DTB: 0x%lx'%(dtb)
        self.dtb = dtb # __init_end in system.map
        self.cache = None
        self._cache_values() # defines pde_cache

    def search(self, bytestr):
        self.local_mmap.find(bytestr)

    def vtop(self, vaddr):
        '''
        Translates virtual addresses into physical offsets.
        The function should return either None (no valid mapping)
        or the offset in physical memory where the address maps.
        '''
        print 'vtop vaddr: 0x%lx'%vaddr,
        pde_value = self.get_pde(vaddr)
        if not self.entry_present(pde_value):
            # Add support for paged out PDE
            # (insert buffalo here!)
            print ' = pde entry not present in pde 0x%s'%(pde_value)
            return None

        if self.page_size_flag(pde_value):
            print ' = 4 MB paddr'
            return self.get_four_meg_paddr(vaddr, pde_value)

        pte_value = self.get_pte(vaddr, pde_value)
        if not self.entry_present(pte_value):
            # Add support for paged out PTE
            print ' = pte entry not present in pte 0x%s'%(pte_value)
            return None

        return self.get_phys_addr(vaddr, pte_value)

    def get_pde(self, vaddr):
        ''' Return the Page Directory Entry for the given virtual address.  '''
        if self.cache:
            return self.pde_cache[self.pde_index(vaddr)]

        pde_addr = (self.dtb & 0xfffff000) | ((vaddr & 0xffc00000) >> 20)
        ret = self.read_long_phys(pde_addr)
        log.debug('get_pde pde_addr: %lx value: 0x%s'%(pde_addr, ret))
        return ret
        
    def pde_index(self, vaddr):
        ''' Returns the Page Directory Entry Index number from the given
            virtual address. The index number is in bits 31:22.   '''
        log.debug('pde_index: %lx'%(vaddr >> 22))
        return vaddr >> 22

    def _cache_values(self):
        '''
        We cache the Page Directory Entries to avoid having to 
        look them up later. There is a 0x1000 byte memory page
        holding the four byte PDE. 0x1000 / 4 = 0x400 entries
        '''
        #buf = self.base.read(self.dtb, 0x1000)
        log.debug('caching DTB values from 0x%lx'%self.dtb)
        buf = self.readBytes(self.dtb, 0x1000) # bstr expected
        if buf is None:
            self.cache = False
        else:
            self.pde_cache = struct.unpack('<' + 'I' * 0x400, buf)

    def read_long_phys(self, addr):
        '''
        Returns an unsigned 32-bit integer from the address addr in
        physical memory. If unable to read from that location, returns None.
        '''
        if addr > len(self.local_mmap):
          return None
        word = ctypes.c_ulong.from_buffer_copy(self.local_mmap, addr).value # is non-aligned a pb ?
        return word
        #return self.readWord(addr)

    def entry_present(self, entry):
        '''   Returns whether or not the 'P' (Present) flag is on in the given entry '''
        if entry:
            return (entry & 1) == 1
        return False

    def page_size_flag(self, entry):
        ''' Returns whether or not the 'PS' (Page Size) flag is on in the given entry '''
        if entry:
            return (entry & (1 << 7)) == (1 << 7)
        return False

    def get_four_meg_paddr(self, vaddr, pde_value):
        return  (pde_value & 0xffc00000) | (vaddr & 0x3fffff)

    def get_pte(self, vaddr, pde_value):
        ''' Return the Page Table Entry for the given virtual address and Page Directory Entry. '''
        pte_addr = (pde_value & 0xfffff000) | ((vaddr & 0x3ff000) >> 10)
        return self.read_long_phys(pte_addr)

    def get_phys_addr(self, vaddr, pte_value):
        ''' Return the offset in a 4KB memory page from the given virtual address and Page Table Entry. '''
        ret = (pte_value & 0xfffff000) | (vaddr & 0xfff)
        print 'paddr: 0x%lx'%ret
        return ret
        

    def get_available_pages(self):
        '''
        Return a list of lists of available memory pages.
        Each entry in the list is the starting virtual address 
        and the size of the memory page.
        '''
        # Pages that hold PDEs and PTEs are 0x1000 bytes each.
        # Each PDE and PTE is four bytes. Thus there are 0x1000 / 4 = 0x400
        # PDEs and PTEs we must test

        for pde in range(0, 0x400):
            vaddr = pde << 22
            pde_value = self.get_pde(vaddr)
            if not self.entry_present(pde_value):
                continue
            if self.page_size_flag(pde_value):
                yield (vaddr, 0x400000)
            else:
                tmp = vaddr
                for pte in range(0, 0x400):
                    vaddr = tmp | (pte << 12)
                    pte_value = self.get_pte(vaddr, pde_value)
                    if self.entry_present(pte_value):
                        yield (vaddr, 0x1000)



