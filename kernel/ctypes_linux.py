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
from haystack.model import is_valid_address,getaddress,array2bytes,bytes2array,LoadableMembers
from haystack.model import RangeValue,NotNull,CString
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


# replace c_char_p with our String handler
if type(gen.STRING) != type(CString):
  print 'STRING is not model.CString. Please correct ctypes_nss_geenrated with :' 
  print 'from model import CString' 
  print 'STRING = CString' 
  import sys
  sys.exit()

# set expected values 
gen.task_struct.expectedValues={
  'pid': RangeValue(1,65535),
  #'tgid': RangeValue(1,65535),
#  'flags': RangeValue(1,0xffffffff), #sched.h:1700 , 1 or 2 bits on each 4 bits group
#  'files': NotNull, # guessing
#  'fs': NotNull, # guessing
#  'comm': NotNull, # process name
}

log.debug('There is %d members in %s'%(len(gen.__dict__), gen.__name__))




def printSizeof(mini=-1):
  for (name,klass) in inspect.getmembers(sys.modules[__name__], inspect.isclass):
    if type(klass) == type(ctypes.Structure) and 'ctypes_linux_generated' in klass.__module__  :
      if ctypes.sizeof(klass) > mini:
        print '%s:'%name,ctypes.sizeof(klass)

if __name__ == '__main__':
  printSizeof(200)

