#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import argparse, os, logging, sys, time, pickle, struct
import itertools

import ctypes
import haystack 
from haystack import abouchet 
import kernel
from kernel import ctypes_linux
from kernel.mappings import JKIA32PagedMemoryPae,JKIA32PagedMemory

log=logging.getLogger('tasks')


KADDRSPACE=0xc0000000

def initMemdump(args):
  base_offset= getBaseOffset(args.system_map_file)
  dtb = getDTB(args.system_map_file)
  fsize = os.fstat(args.memdump.fileno()).st_size
  mem = JKIA32PagedMemoryPae(args.memdump, 0, fsize, dtb) #base_offset ) ## is that valid ?
  #mem = JKIA32PagedMemory(args.memdump, 0, fsize, dtb) #base_offset ) ## is that valid ?
  
  mappings = kernel.mappings.readKernelMemoryMappings2(mem)

  log.debug('memdump initialised %s'%(mappings[0]))
  return mappings

def getBaseOffset(systemmap):
  systemmap.seek(0)
  for l in systemmap.readlines():
    if 'T startup_32' in l:
      addr,d,n = l.split()
      log.info('found base_offset @ %s'%(addr))
      return int(addr,16)
  return None


def getInitTask(systemmap):
  systemmap.seek(0)
  for l in systemmap.readlines():
    if 'D init_task' in l:
      addr,d,n = l.split()
      log.info('found init_task @ %s'%(addr))
      return int(addr,16)
  return None
  
def getDTB(systemmap):
  ## ! since when the DTB is __init_end ?
  '''
  c03bc000 B __bss_start
  c03bc000 B __init_end
  c03bc000 B swapper_pg_dir
  '''
  name='swapper_pg_dir'
  systemmap.seek(0)
  for l in systemmap.readlines():
    if name in l:
      addr,d,n = l.split()
      log.info('found DTB/%s @ %s'%(name,addr))
      return int(addr,16) - KADDRSPACE 
  return None

def argparser():
  parser = argparse.ArgumentParser(prog='tasks', description='List tasks from memdump.')
  parser.add_argument('memdump', type=argparse.FileType('r'), help='memdump file')
  parser.add_argument('system_map_file', type=argparse.FileType('r'), help='system.map file')
  parser.set_defaults(func=search)
  return parser

def search(args):
  
  memdump = args.memdump
  structType = ctypes_linux.task_struct
  initTaskAddr = getInitTask(args.system_map_file)
  #dtb = getDTB(args.system_map_file)

  mappings = initMemdump(args)
  finder = abouchet.StructFinder(mappings)
  print 'mappings[0] ' ,mappings[0]
  #print 'myread : %s'%(mappings[0]._local_mmap[initTaskAddr:initTaskAddr+200])
  print 'initTaskAddr vaddr:0x%x paddr:0x%x'%(initTaskAddr, mappings[0].vtop(initTaskAddr))
  outs = finder.loadAt( mappings[0] , initTaskAddr , structType, depth=10)

  print outs
  
  swapper = outs[0]
  print swapper.tasks
  for m in mappings:
    if swapper.tasks.next in m:
      print 'next is in ', m
    if initTaskAddr in m:
      print 'inittask in ', m

  return 0


def main(argv):
  logging.basicConfig(level=logging.DEBUG)
  logging.getLogger('model').setLevel(logging.INFO)

  parser = argparser()
  opts = parser.parse_args(argv)
  try:
    opts.func(opts)
  except ImportError,e:
    log.error('Struct type does not exists.')
    print e

  #0xb9116268

  return 0
  



if __name__ == "__main__":
  main(sys.argv[1:])




