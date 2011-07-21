import ctypes, struct, mmap, logging
# local
from haystack.memory_mapping import MemoryDumpMemoryMapping 
# TODO check ctypes_tools.bytes2array in ptrace

log = logging.getLogger('mappings')

'''
Shameless steal from volatility/plugins/addrspaces/intel.py
'''

class JKIA32PagedMemory(MemoryDumpMemoryMapping):
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
        self.memdump = memdump
        self._local_mmap = mmap.mmap(memdump.fileno(), end-start, access=mmap.ACCESS_READ)
        ###
        #print 'DTB: 0x%lx'%(dtb)
        self.dtb = dtb # __init_end in system.map
        self.cache = None
        self._cache_values() # defines pde_cache

    def search(self, bytestr):
        self._local_mmap.find(bytestr)

    def vtop(self, vaddr):
        '''
        Translates virtual addresses into physical offsets.
        The function should return either None (no valid mapping)
        or the offset in physical memory where the address maps.
        '''
        #print 'vtop vaddr: 0x%lx'%vaddr,
        pde_value = self.get_pde(vaddr)
        if not self.entry_present(pde_value):
            # Add support for paged out PDE
            # (insert buffalo here!)
            return None

        if self.page_size_flag(pde_value):
            return self.get_four_meg_paddr(vaddr, pde_value)

        pte_value = self.get_pte(vaddr, pde_value)
        if not self.entry_present(pte_value):
            # Add support for paged out PTE
            return None

        return self.get_phys_addr(vaddr, pte_value)

    def get_pde(self, vaddr):
        ''' Return the Page Directory Entry for the given virtual address.  '''
        if self.cache:
            log.debug('get_pde: self.cache is True')
            return self.pde_cache[self.pde_index(vaddr)]
        #log.debug('(self.dtb & 0xfffff000):0x%x | ((vaddr & 0xffc00000) >> 20):0x%x'%((self.dtb & 0xfffff000) , ((vaddr & 0xffc00000) >> 20)))
        pde_addr = (self.dtb & 0xfffff000) | ((vaddr & 0xffc00000) >> 20)
        ret = self.read_long_phys(pde_addr)
        #log.debug('get_pde pde_addr: 0x%lx value: 0x%s'%(pde_addr, ret))
        return ret
        
    def pde_index(self, vaddr):
        ''' Returns the Page Directory Entry Index number from the given
            virtual address. The index number is in bits 31:22.   '''
        #log.debug('pde_index: %lx'%(vaddr >> 22))
        return vaddr >> 22

    def _cache_values(self):
        '''
        We cache the Page Directory Entries to avoid having to 
        look them up later. There is a 0x1000 byte memory page
        holding the four byte PDE. 0x1000 / 4 = 0x400 entries
        '''
        #buf = self.base.read(self.dtb, 0x1000)
        log.debug('caching DTB values from 0x%lx (real:0x%x)'%(self.dtb, self.dtb))
        #buf = self.readBytes(self.dtb, 0x1000) # bstr expected
        buf = (ctypes.c_ulong*0x400).from_buffer_copy(self._local_mmap, self.dtb)#.value 
        if buf is None:
            self.cache = False
        else:
            self.pde_cache = struct.unpack('<' + 'I' * 0x400, buf)
        log.debug('caching done')

    def read_long_phys(self, addr):
        '''
        Returns an unsigned 32-bit integer from the address addr in
        physical memory. If unable to read from that location, returns None.
        '''
        if addr > len(self._local_mmap):
          log.warning('addr 0x%x > size:0x%x'%(addr,len(self._local_mmap)))
          return None
        word = ctypes.c_ulong.from_buffer_copy(self._local_mmap, addr).value # is non-aligned a pb ?
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
        ret = ((pte_value & 0xfffff000) | (vaddr & 0xfff))
        #log.debug( 'phys_addr: 0x%lx'%ret)
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



class JKIA32PagedMemoryPae(JKIA32PagedMemory):
    def _cache_values(self):
        ''' Q * 4 ?'''
        buf = (ctypes.c_ulonglong*4).from_buffer_copy(self._local_mmap, self.dtb)#.value 
        #buf = self.base.read(self.dtb, 0x20)
        if buf is None:
            self.cache = False
        else:
            self.pdpte_cache = struct.unpack('<' + 'Q' * 4, buf)

    def pdpte_index(self, vaddr):
        '''
        Compute the Page Directory Pointer Table index using the
        virtual address.

        The index comes from bits 31:30 of the original linear address.
        '''
        return vaddr >> 30

    def get_pdpte(self, vaddr):
        '''
        Return the Page Directory Pointer Table Entry for the given
        virtual address. Uses the cache if available, otherwise:

        Bits 31:5 come from CR3
        Bits 4:3 come from bits 31:30 of the original linear address
        Bits 2:0 are all 0
        '''
        if self.cache:
            return self.pdpte_cache[self.pdpte_index(vaddr)]

        pdpte_addr = (self.dtb & 0xffffffe0) | ((vaddr & 0xc0000000) >> 27)
        #print('get_pdpte: pdpte_addr:0x%x from self.dtb 0x%x and vaddr:0x%x '%(pdpte_addr,self.dtb,vaddr))
        return self._read_long_long_phys(pdpte_addr)

    def get_pde(self, vaddr, pdpte):
        '''
        Return the Page Directory Entry for the given virtual address
        and Page Directory Pointer Table Entry.

        Bits 51:12 are from the PDPTE
        Bits 11:3 are bits 29:21 of the linear address
        Bits 2:0 are 0
        '''
        pde_addr = (pdpte & 0xffffffffff000) | ((vaddr & 0x3fe00000) >> 18)
        #print('get_pde: pde_addr:0x%x from pdpte 0x%x and vaddr:0x%x '%(pde_addr,pdpte,vaddr))
        return self._read_long_long_phys(pde_addr)


    def get_two_meg_paddr(self, vaddr, pde):
        '''
        Return the offset in a 2MB memory page from the given virtual
        address and Page Directory Entry.

        Bits 51:21 are from the PDE
        Bits 20:0 are from the original linear address
        '''
        return (pde & 0xfffffffe00000) | (vaddr & 0x1fffff)

    def get_pte(self, vaddr, pde):
        '''
        Return the Page Table Entry for the given virtual address
        and Page Directory Entry.

        Bits 51:12 are from the PDE
        Bits 11:3 are bits 20:12 of the original linear address
        Bits 2:0 are 0
        '''
        pte_addr = (pde & 0xffffffffff000) | ((vaddr & 0x1ff000) >> 9)
        #print('get_pte: pte_addr:0x%x from pde 0x%x and vaddr:0x%x '%(pte_addr,pde,vaddr))
        return self._read_long_long_phys(pte_addr)

    def get_phys_addr(self, vaddr, pte):
        '''
        Return the offset in a 4KB memory page from the given virtual
        address and Page Table Entry.

        Bits 51:12 are from the PTE
        Bits 11:0 are from the original linear address
        '''
        return ((pte & 0xffffffffff000) | (vaddr & 0xfff) )


    def vtop(self, vaddr):
        '''
        Translates virtual addresses into physical offsets.
        The function returns either None (no valid mapping)
        or the offset in physical memory where the address maps.
        '''
        
        
        pdpte = self.get_pdpte(vaddr)
        #log.debug('pdpte: @0x%x = 0x%x'%(vaddr,pdpte))
        if not self.entry_present(pdpte):
            # Add support for paged out PDPTE
            # Insert buffalo here!
            raise ValueError('pdpte is not present')
            return None

        pde = self.get_pde(vaddr, pdpte)
        #log.debug('pde: @0x%x = 0x%x'%(vaddr,pde))
        if not self.entry_present(pde):
            # Add support for paged out PDE
            raise ValueError('pde is not present')
            return None

        if self.page_size_flag(pde):
            return self.get_two_meg_paddr(vaddr, pde)

        pte = self.get_pte(vaddr, pde)
        if not self.entry_present(pte):
            # Add support for paged out PTE
            raise ValueError()
            return None
        
        return self.get_phys_addr(vaddr, pte)

    def _read_long_long_phys(self, addr):
        '''
        Returns an unsigned 64-bit integer from the address addr in
        physical memory. If unable to read from that location, returns None.
        '''
        raddr = int(addr)
        #print('_read_long_long_phys(0x%x):'%(raddr))
        #string = self.base.read(addr, 8)
        if raddr > len(self._local_mmap):
          log.warning('_read_long_long addr 0x%x > size:0x%x'%(raddr,len(self._local_mmap)))
          raise ValueError()
          return None
        word = ctypes.c_ulonglong.from_buffer_copy(self._local_mmap, raddr).value # is non-aligned a pb ?
        return word

    def get_available_pages(self):
        '''
        Return a list of lists of available memory pages.
        Each entry in the list is the starting virtual address 
        and the size of the memory page.
        '''

        # Pages that hold PDEs and PTEs are 0x1000 bytes each.
        # Each PDE and PTE is eight bytes. Thus there are 0x1000 / 8 = 0x200
        # PDEs and PTEs we must test.
        for pdpte in range(0, 4):
            vaddr = pdpte << 30
            #log.debug('get_available_pages: @0x%x'%(vaddr))
            pdpte_value = self.get_pdpte(vaddr)
            if not self.entry_present(pdpte_value):
                continue
            for pde in range(0, 0x200):
                vaddr = pdpte << 30 | (pde << 21)
                pde_value = self.get_pde(vaddr, pdpte_value)
                if not self.entry_present(pde_value):
                    continue
                if self.page_size_flag(pde_value):
                    #print '***yield a page size flag'
                    yield (vaddr, 0x200000)
                    continue

                tmp = vaddr
                for pte in range(0, 0x200):
                    vaddr = tmp | (pte << 12)
                    pte_value = self.get_pte(vaddr, pde_value)
                    if self.entry_present(pte_value):
                        #print 'pte_value 0x%x'%(pte_value)
                        yield (vaddr, 0x1000)
                    

def readKernelMemoryMappings(kernelMemory):
  maps = []
  total = 0
  laststart=-1
  lastend=-1
  for addr,s in kernelMemory.get_available_pages():
    if laststart == -1:
      laststart = addr
    elif lastend != addr:
      if lastend  > addr : # overlapping ?
        raise ValueError()
      #gap found, save previous mmap
      p = kernelMemory.vtop(laststart)
      if p > len(kernelMemory):
        #raise ValueError('cant read after end of file... 0x%x'%(p))
        log.warning('cant read after end of file... 0x%x'%(p))
      offset = p 
      maps.append(MemoryDumpMemoryMapping(kernelMemory.memdump, start=laststart, end=lastend, offset=offset, preload=False))
      #log.debug('0x%x-0x%x (0x%x)\t@\t0x%x'%(laststart,lastend,lastend-laststart,p))
      print('0x%x - 0x%x'%(laststart,lastend))
      total += (lastend-laststart)
      # new
      laststart = addr
    # next
    lastend = addr+s
  # save last
  p = kernelMemory.vtop(laststart)
  offset = p # pte_value)
  maps.append(MemoryDumpMemoryMapping(kernelMemory.memdump, start=laststart, end=lastend, offset=offset, preload=False))
  log.debug('0x%x-0x%x (0x%x)\t@\t0x%x'%(laststart,lastend,lastend-laststart,offset))
  print('0x%x - 0x%x'%(laststart,lastend))
  total += (lastend-laststart)
      
  log.debug( '%s 0x%x'%(total, total))
  return maps




    

