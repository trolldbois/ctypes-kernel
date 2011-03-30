#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import logging, re

log=logging.getLogger('preprocess')

class HeaderCleaner:
  '''
    Cleans a Preprocessed File for gccxml comsumption.
    Strips off static functions and extern references.
    
    @param preprocessed: the preprocessed file name
    @param out: the desired output file
  '''
  def __init__(self, preprocessed, out):
    self.preprocessed = file(preprocessed).read()
    self.out = out
    
  def stripFunctions(self, data):
    REGEX_STR = r"""  # nice - ok for pointers
    ^ (__attribute__\(\(no_instrument_function\)\)\s+)* ((static\ (inline|__inline__)) 
           (\s+__attribute__\(\(always_inline\)\))*  (?P<sig> \s+\w+)* (\s*[*]\s*)* 
                  (?P<funcname>  \w+ ) (?P<args> \([^{;]+?\)\s* ) 
          ( { . }$ | {  .*?  ^}$  )
      )     
     """
    REGEX_OBJ = re.compile(REGEX_STR, re.MULTILINE| re.VERBOSE | re.DOTALL)
    data2 = REGEX_OBJ.sub('// supprimed function',data)
    return data2


  def stripExterns(self, data):
    REGEX_STR2 = r"""  # 
  ^((extern) \s+ (?!struct|enum) .*? ;$  ) 
   """
    REGEX_OBJ2 = re.compile(REGEX_STR2, re.MULTILINE| re.VERBOSE | re.DOTALL)
    data3 = REGEX_OBJ2.sub('// supprimed extern', data)
    return data3

  def changeReservedWords(self, data):
    data1 = data.replace('*new);','*new1);')
    mre = re.compile(r'\bprivate;')
    data2 = mre.sub('private1;',data1)
    mre = re.compile(r'\bnamespace\b')
    data3 = mre.sub('namespace1',data2)
    return data3

  def clean(self):
    data2 = self.stripFunctions(self.preprocessed)
    data3 = self.stripExterns(data2)
    data4 = self.changeReservedWords(data3)
    self.fout = file(self.out,'w')
    return self.fout.write(data4)



def clean(prepro, out):
  clean = HeaderCleaner(prepro, out)
  return clean.clean()

#clean('ctypes_linux_generated.c','ctypes_linux_generated_clean.c')
