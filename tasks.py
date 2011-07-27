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
  mapp0=None
  finder = abouchet.StructFinder(mappings)
  for m in mappings:
    if initTaskAddr in m:
      mapp0=m
      break
  if not mapp0:
    raise ValueError('0x%x is not in any mappings'%(initTaskAddr))
  outs = finder.loadAt( mapp0 , initTaskAddr , structType, depth=10)

  #print outs[0]
  swapper = outs[0]
  
  task = swapper.getTasksNext()
  print '%s\t\t%d'%(swapper.comm,swapper.pid)
  print swapper.toString()
  while task.pid != 0:
    print '%s\t\t%d'%(task.comm,task.pid)#,swapper.cred.contents.uid)
    #print task.toString()
    task = task.getTasksNext()
  
  return 0  
  swapper = swapper.toPyObject()
  task = swapper.tasks.next
  print '%s\t\t%d\t\t%d'%(swapper.comm,swapper.pid,0)#swapper.cred.uid)
  print swapper.toString()
  while task.pid != 0:
    print '%s\t\t%d\t\t%d'%(task.comm,task.pid,swapper.cred.uid)
    #print task.toString()
    task = task.tasks.next
  return 0


def main(argv):
  logging.basicConfig(level=logging.INFO)
  logging.getLogger('model').setLevel(logging.INFO)
  #logging.getLogger('ctypes_linux').setLevel(logging.INFO)

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




