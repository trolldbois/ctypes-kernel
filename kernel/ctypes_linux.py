#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import ctypes
import logging
import sys

from haystack import model
from haystack.model import is_valid_address,is_valid_address_value,pointer2bytes,array2bytes,bytes2array,getaddress,offsetof
from haystack.model import LoadableMembers,RangeValue,NotNull,CString, IgnoreMember

import ctypes_linux_generated as gen

log=logging.getLogger('ctypes_linux')


class KernelStruct(LoadableMembers):
  ''' defines classRef '''
  pass

################ START copy generated classes ##########################

# copy generated classes (gen.*) to this module as wrapper
model.copyGeneratedClasses(gen, sys.modules[__name__])

# register all classes (gen.*, locally defines, and local duplicates) to haystack
# create plain old python object from ctypes.Structure's, to picke them
model.registerModule(sys.modules[__name__])

################ END   copy generated classes ##########################


# set expected values 
gen.task_struct.expectedValues={
  'pid': RangeValue(0,65535), #0 for swapper/initTask
  #'tgid': RangeValue(1,65535),
#  'flags': RangeValue(1,0xffffffff), #sched.h:1700 , 1 or 2 bits on each 4 bits group
#  'files': NotNull, # guessing
#  'fs': NotNull, # guessing
#  'comm': NotNull, # process name
}

def task_struct_loadMembers(self, mappings, maxDepth=99, task_cache=set()):
    head = False # howto return True
    if len(task_cache) == 0:
      head = True
    if getaddress(self) in task_cache:
      return task_cache #already in cache task_cache[self.tasks.next] # finish
    # else load tasks.(list_head).next as a task_struct and get_tasks from it
    task_cache.add( getaddress(self) )
    #for t in task_cache:
    #  print hex(t)

    # next and prev
    addr_prev = getaddress(self.tasks.prev)-offsetof(task_struct,'tasks')
    addr_next = getaddress(self.tasks.next)-offsetof(task_struct,'tasks')
    if addr_prev == addr_next:
      log.debug('only one element in list')
    print hex(addr_prev),hex(addr_next), hex(getaddress(self))

    super(task_struct,self).loadMembers(mappings, maxDepth-1)
    log.debug("Loaded task_struct for process '%s'"%(self.comm))

    mapp0 = [m for m in mappings if 0xf74701b0 in m]
    #print ' **** mappings containing initTask.tasks.next : ' ,mapp0[0]
    #print ' next is ', self.tasks.next
    
    log.debug('re-loading task_struct.tasks.next from 0x%x'%(addr_next))
    field = dict([ (f[0],f[1]) for f in self._fields_])
    # recursive loading
    attr = self.tasks.next
    attrname = 'tasks.next'
    attrtype = gen.task_struct
    memoryMap = is_valid_address_value( addr_next, mappings, attrtype)
    if(not memoryMap):
      # big BUG Badaboum, why did pointer changed validity/value ?
      log.warning("%s %s not loadable 0x%lx but VALID "%(attrname, attr, addr_next ))
      #attr.contents = 0
    else:
      log.debug("self.tasks.next-> 0x%lx (is_valid_address_value: %s)"%(addr_next, memoryMap ))
      # save the total struct to local memspace
      #tmp = attrtype.from_buffer_copy(memoryMap.readStruct(addr_next, attrtype ))
      tmp = memoryMap.readStruct(addr_next, attrtype )
      log.debug("%s is loaded: '%s'"%(attrname, tmp.comm))
      # fake a cast
      attr.contents = gen.list_head.from_address(getaddress(tmp.tasks)) #loadMember is done
      # be torough and load list members
      log.debug("%s loaded memcopy from 0x%lx to 0x%lx"%(attrname,  addr_next, (getaddress(attr))   ))
      # recursive validation checks on new struct
      if not bool(attr):
        log.warning('Member %s is null after copy: %s'%(attrname,attr))
      elif not tmp.loadMembers(mappings, maxDepth-1, task_cache):
        # go and load the pointed struct members recursively
        log.debug('member %s was not loaded'%(attrname))
    if not head:
      return task_cache
    return True


gen.task_struct.loadMembers = task_struct_loadMembers


def list_head_loadMembers(self, mappings, maxDepth):
  ''' 
  list can't be self loaded. they need to be handled by the enclosing Structure.
  next and prev are pointers to <enclosing Structure> instances.
  ptrace memory copy (_loadMembers) must be done by enclosing Structure.
  '''
  return True

gen.list_head.loadMembers = list_head_loadMembers


log.debug('There is %d members in %s'%(len(gen.__dict__), gen.__name__))




def printSizeof(mini=-1):
  for (name,klass) in inspect.getmembers(sys.modules[__name__], inspect.isclass):
    if type(klass) == type(ctypes.Structure) and 'ctypes_linux_generated' in klass.__module__  :
      if ctypes.sizeof(klass) > mini:
        print '%s:'%name,ctypes.sizeof(klass)




if __name__ == '__main__':
  printSizeof(200)

