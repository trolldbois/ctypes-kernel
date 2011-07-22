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
from haystack.model import is_valid_address,is_valid_address_value,pointer2bytes,array2bytes,bytes2array,getaddress
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

def task_struct_loadMembers(self, mappings, maxDepth, loadedTasks=set()):
    #if maxDepth == 0:
    #  return True
    if getaddress(self.tasks.next) in loadedTasks:
      return True # finish
    log.debug('re-loading tasks from %s 0x%x'%(self.comm, getaddress(self.tasks.next)))
    field = dict([ (f[0],f[1]) for f in self._fields_])
    tasks=getattr(self,'tasks')

    # next and prev
    next=getattr(tasks,'next')
    prev=getattr(tasks,'prev')
    addr_prev=getaddress(prev)
    addr_next=getaddress(next)
    if addr_prev == addr_next:
      log.debug('only one element in list')
      maxDepth=1
    attr = next
    # iterative loading 
    #while getaddress(attr) not in loadedTasks:
    # recursive loading
    attrname = 'tasks.next'
    attrtype = ctypes.POINTER(gen.task_struct)
    memoryMap = is_valid_address( attr, mappings, attrtype)
    if(not memoryMap):
      # big BUG Badaboum, why did pointer changed validity/value ?
      log.warning("%s %s not loadable 0x%lx but VALID "%(attrname, attr, addr_next ))
      return True
    log.debug("%s %s loading from 0x%lx (is_valid_address: %s)"%(attrname,attr,addr_next, memoryMap ))
    # save the total struct to local memspace
    tmp = attrtype.from_buffer_copy(memoryMap.readStruct(addr_next, attrtype ))
    # fake a cast
    attr.contents = gen.list_head.from_address(getaddress(tmp))
    #####
    log.debug("%s %s loaded memcopy from 0x%lx to 0x%lx"%(attrname, attr, addr_next, (getaddress(attr))   ))
    # recursive validation checks on new struct
    if not bool(attr):
      log.warning('Member %s is null after copy: %s'%(attrname,attr))
      return True
    #flag it  
    loadedTasks.add( getaddress(self.tasks.next) )
    print loadedTasks
    # go and load the pointed struct members recursively
    if not tmp.contents.loadMembers(mappings, maxDepth-1,loadedTasks):
      log.debug('member %s was not loaded'%(attrname))
      return False
    return LoadableMembers.loadMembers(self,mappings,maxDepth-1)
    #return True

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

