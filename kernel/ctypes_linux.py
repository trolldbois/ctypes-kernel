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
  #'tgid': RangeValue(1,65535),
#  'flags': RangeValue(1,0xffffffff), #sched.h:1700 , 1 or 2 bits on each 4 bits group
#  'files': NotNull, # guessing
#  'fs': NotNull, # guessing
#  'comm': NotNull, # process name
}

# beuargh, k: (pid,name)
''' we need a global tasks cache to keep ref to loaded tasks/pointers.'''

def task_struct_loadMembers(self, mappings, maxDepth=99):
    # next and prev
    addr_prev = getaddress(self.tasks.prev)-offsetof(task_struct,'tasks')
    addr_next = getaddress(self.tasks.next)-offsetof(task_struct,'tasks')
    LoadableMembers.loadMembers(self,mappings, 5)
    log.debug("Loaded task_struct for process '%s'"%(self.comm))
    #check cache and bail
    attr = self.tasks.next
    attrname = 'tasks.next'
    attrtype = gen.task_struct
    cache = model.getRef(attrtype ,addr_next )
    if cache:
      nextTask = cache
      # get the offset into the buffer and associate the .tasks->next to it
      attr.contents = gen.list_head.from_address(ctypes.addressof(nextTask.tasks)) #loadMember is done
      # be torough and load list members
      log.debug("assigned &nextTask.tasks to self.task.next"%( ))
      return True
    # load it
    log.debug('re-loading task_struct.tasks.next from 0x%x'%(addr_next))
    # recursive loading
    memoryMap = is_valid_address_value( addr_next, mappings, attrtype)
    if(not memoryMap):
      # big BUG Badaboum, why did pointer changed validity/value ?
      log.warning("%s %s not loadable 0x%lx but VALID "%(attrname, attr, addr_next ))
      return True
    else:
      log.debug("self.tasks.next-> 0x%lx (is_valid_address_value: %s)"%(addr_next, memoryMap ))
      # save the total struct to local memspace
      nextTask = memoryMap.readStruct(addr_next, attrtype )
      log.debug("%s is loaded: '%s'"%(attrname, nextTask.comm))
      # save the ref and load the task
      model.keepRef( nextTask, attrtype, addr_next)
      # get the offset into the buffer and associate the .tasks->next to it
      attr.contents = gen.list_head.from_address(ctypes.addressof(nextTask.tasks)) #loadMember is done
      # be torough and load list members
      log.debug("assigned &nextTask.tasks to self.task.next"%( ))
      # recursive validation checks on new struct
      if not bool(attr):
        log.warning('Member %s is null after copy: %s'%(attrname,attr))
      else:
        return nextTask.loadMembers(mappings, maxDepth-1)
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

gen.list_head.loadMembers = list_head_loadMembers


log.debug('There is %d members in %s'%(len(gen.__dict__), gen.__name__))




def printSizeof(mini=-1):
  for (name,klass) in inspect.getmembers(sys.modules[__name__], inspect.isclass):
    if type(klass) == type(ctypes.Structure) and 'ctypes_linux_generated' in klass.__module__  :
      if ctypes.sizeof(klass) > mini:
        print '%s:'%name,ctypes.sizeof(klass)




if __name__ == '__main__':
  printSizeof(200)

