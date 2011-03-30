#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import logging, os, subprocess

log=logging.getLogger('preprocess')

class Preprocess:
  '''
    Make a Preprocessed File from a C file
    
    @param cfile: the desired input c file name
    @param preprocessed: the preprocessed file name
  '''
  def __init__(self, cfile, preprocessed, gcc='gcc', kheaders=None, arch='x86'):
    self.cfile = cfile
    self.preprocessed = preprocessed
    self.gcc = 'gcc'
    self.arch = arch
    self.kheaders = kheaders
  
  def getKheaders(self):
    if self.kheaders is None:
      p = subprocess.Popen(['uname', '-r'], stdin=None, stdout=subprocess.PIPE, close_fds=True )
      p.wait()
      build = p.stdout.read().strip()
      self.kheaders = "/usr/src/linux-headers-%s/"%(build)
    return self.kheaders 
  
  def getArchInc(self):
    self.archinc = "%s/arch/%s/include"%(self.getKheaders(), self.arch)
    return self.archinc
  
  def getEnviron(self):
    env = os.environ
    env['ARCHINC'] = self.getArchInc()    
    env['KHEADERS'] = self.getKheaders()    
    return env

  def run(self):
    self.getArchInc()    
    self.getKheaders()    
    cmd_line = [self.gcc, '-std=c++98', '-x', 'c++', 'ctypes_linux.c', '-P', '-E', '-nostdinc',  '-D', '__KERNEL__', 
      '-I%s'%(self.archinc), '-I%s/include'%(self.kheaders),
      '-include', '%s/include/generated/autoconf.h'%(self.kheaders), 
      '-isystem', '/usr/lib/gcc/i686-linux-gnu/4.4.5/include', '-I/usr/src/linux-headers-lbm-',
      '-Wall', '-Wundef', '-Wno-trigraphs', '-fno-strict-aliasing', '-fno-common', '-Wno-format-security', '-fno-delete-null-pointer-checks', '-O2', 
      '-m32', '-msoft-float', '-mregparm=3', '-freg-struct-return', '-mpreferred-stack-boundary=2', '-march=i686', '-mtune=generic', 
      '-maccumulate-outgoing-args', '-ffreestanding', '-fstack-protector', '-DCONFIG_AS_CFI=1', '-DCONFIG_AS_CFI_SIGNAL_FRAME=1', 
      '-DCONFIG_AS_CFI_SECTIONS=1', '-Wno-sign-compare', '-fno-asynchronous-unwind-tables', '-o', self.preprocessed]
    p = subprocess.Popen(cmd_line, stdin=None, stdout=subprocess.PIPE, close_fds=True, env=self.getEnviron())
    p.wait()
    build = p.stdout.read().strip()
    if len(build) == 0:
      log.info("GENERATED ctypes_linux_generated.c - please correct source code gccxml is gonna choke on kernel source code")
    else:
      log.info(build)
    return len(build)


def process(cfile, preprocessed, kheaders=None, arch='x86'):
  p = Preprocess(cfile, preprocessed, kheaders=kheaders, arch=arch)
  return p.run()

#clean('ctypes_linux_generated.c','ctypes_linux_generated_clean.c')
