#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import ctypes
import logging
import sys

import haystack
from haystack import model
from haystack.model import is_valid_address,is_valid_address_value,pointer2bytes,array2bytes,bytes2array,getaddress
from haystack.model import offsetof,container_of, keepRef
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
  'real_parent' : IgnoreMember, # should be Ignore Loading really
  'tgid': RangeValue(0,65535),
  'flags': RangeValue(1,0xffffffff), #sched.h:1700 , 1 or 2 bits on each 4 bits group
  'files': NotNull, # guessing
  'fs': NotNull, # guessing
  'comm': NotNull, # process name
}

# beuargh, k: (pid,name)
''' we need a global tasks cache to keep ref to loaded tasks/pointers.'''

def task_struct_loadMembers(self, mappings, maxDepth=99):
  listHeads= [('cg_list',  task_struct),
              ('children', None), # core dump on 'task_struct'
              ('cpu_timers', None), # array of 3
              ('perf_event_list', None),
              ('pi_state_list', None),
              ('pi_waiters', None),
              ('preempt_notifiers', None), # ?
              ('ptraced', None),
              ('ptrace_entry', None),
              ('robust_list', None),
              ('sibling', task_struct),
              ('tasks', task_struct),
              ('thread_group', None),
              ]
  offsets=dict()
  for attrname, attrtype in listHeads:
    if attrtype is not None:
      # save next and prev from differential offset
      offsets[(attrname, attrtype)] = getattr(self,attrname).getOffsets(mappings, attrtype, attrname)
  #now, we can map in local space // kinda useless, but hey... we wont hack into ctypes..
  maxDepth = 5
  LoadableMembers.loadMembers(self,mappings, maxDepth)
  log.debug("Loaded task_struct for process '%s'"%(self.comm))  
  # copy real list members memory space size, offseting from list_head member
  for head,addrs in offsets.items():
    attrname, attrtype = head
    # load that list_head members
    getattr(self,attrname).loadRealMembers(mappings, maxDepth, attrtype, attrname, addrs)
  return True

def task_struct_getTasksNext(self):
  ''' once the task_struct is loadMembers(ed), self->tasks.next is loaded to. just a bit hidden'''
  return container_of(getaddress(self.tasks.next), gen.task_struct, 'tasks')
def task_struct_getTasksPrev(self):
  return container_of(getaddress(self.tasks.prev), gen.task_struct, 'tasks')

def task_struct_toPyObject(self):
  my_class=getattr(sys.modules[self.__class__.__module__],"%s_py"%(self.__class__.__name__) )
  #keep ref
  cache = model.getRef(my_class, ctypes.addressof(self) )
  if cache:
    return cache
  obj=model.LoadableMembers.toPyObject(self)
  # change list_head by task_struct
  obj.tasks.next = self.getTasksNext().toPyObject()
  obj.tasks.prev = self.getTasksPrev().toPyObject()

task_struct.loadMembers = task_struct_loadMembers
task_struct.toPyObject = task_struct_toPyObject
task_struct.getTasksNext = task_struct_getTasksNext
task_struct.getTasksPrev = task_struct_getTasksPrev


def list_head_loadMembers(self, mappings, maxDepth):
  ''' 
  list can't be self loaded. they need to be handled by the enclosing Structure.
  next and prev are pointers to <enclosing Structure> instances.
  ptrace memory copy (_loadMembers) must be done by enclosing Structure.
  '''
  return True

def list_head_getOffsets(self, mappings, attrtype, listHeadName):
  '''
    get the prev and next structure's real start addresses.
    we need a real attrtype and the list_head attrname to calculate the offset
    @param attrtype the target structure type
    @param listHeadName the member name in that target structure
  '''
  names = ['prev','next']
  ret = list()
  for name in names:
    addr = getaddress(getattr(self, name))
    log.debug( '0x%x %s.%s'%(addr, listHeadName, name) )
    if addr < 1 or not is_valid_address_value(addr, mappings, attrtype) :
      addr = None
    else:
      addr -= offsetof(attrtype, listHeadName)
    ret.append(addr)
  return (ret[0],ret[1])#(addr_prev,addr_next)

def list_head_loadRealMembers(self, mappings, maxDepth, attrtype, listHeadName, addresses):
  '''
    Copy ->next and ->prev target structure's memeory space.
    attach prev and next correctly.
    @param attrtype the target structure type
    @param listHeadName the member name of the list_head in the target structure
    @param addresses original pointers for prev and next
  '''
  attrname = listHeadName
  addr_prev,addr_next = addresses
  null = list_head()
  for listWay, addr in [('prev',addr_prev),('next',addr_next)]:
    attr = getattr(self,listWay)
    if addr is None or not bool(attr):
      attr.contents = null
      continue # do not load unvalid address
    #print listHeadName,listWay, hex(addr)
    #elif not is_address_local(attr) :
    #  continue # coul
    cache = model.getRef(attrtype, addr ) # is the next/prev Item in cache
    if cache:
      # get the offset into the buffer and associate the .list_head->{next,prev} to it
      attr.contents = gen.list_head.from_address(ctypes.addressof( getattr(cache, attrname)) ) #loadMember is done
      log.debug("assigned &%s.%s in self "%(attrname,listWay ))
      # DO NOT recurse
      continue
    log.debug('re-loading %s.%s.%s from 0x%x'%(attrtype,attrname,listWay, addr))
    memoryMap = is_valid_address_value( addr, mappings, attrtype)
    if(not memoryMap):
      # big BUG Badaboum, why did pointer changed validity/value ?
      log.warning("%s.%s %s not loadable 0x%lx but VALID "%(attrname,listWay, attr, addr ))
      attr.contents = null
      continue
    else:
      log.debug("self.%s.%s -> 0x%lx (is_valid_address_value: %s)"%(attrname,listWay, addr, memoryMap ))
      # save the total struct to local memspace
      nextItem = memoryMap.readStruct(addr, attrtype )
      #if not nextItem.isValid(mappings):
      #  log.warning('%s.%s (%s) is INVALID'%(attrname,listWay, attrtype))
      #  return False
      log.debug("%s.%s is loaded: '%s'"%(attrname,listWay, nextItem ))
      # save the ref and load the task
      model.keepRef( nextItem, attrtype, addr)
      # get the offset into the buffer and associate the .tasks->next to it
      attr.contents = gen.list_head.from_address(ctypes.addressof( getattr(nextItem, attrname) )) #loadMember is done
      log.debug("assigned &%s.%s in self "%(attrname,listWay ))
      # recursive validation checks on new struct
      if not bool(attr):
        log.warning('Member %s.%s is null after copy: %s'%(attrname, listWay ,attr))
        attr.contents = null
      else:
        # recursive loading - model revalidation
        if not nextItem.loadMembers(mappings, maxDepth-1):
          return False
      continue
  return True


gen.list_head.loadMembers = list_head_loadMembers
gen.list_head.getOffsets = list_head_getOffsets
gen.list_head.loadRealMembers = list_head_loadRealMembers

log.debug('There is %d members in %s'%(len(gen.__dict__), gen.__name__))




def printSizeof(mini=-1):
  for (name,klass) in inspect.getmembers(sys.modules[__name__], inspect.isclass):
    if type(klass) == type(ctypes.Structure) and 'ctypes_linux_generated' in klass.__module__  :
      if ctypes.sizeof(klass) > mini:
        print '%s:'%name,ctypes.sizeof(klass)




if __name__ == '__main__':
  printSizeof(200)

