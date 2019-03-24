#!/usr/bin/env python

"""
Copyright (c) 2006-2018 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.HIGHEST

def dependencies():
   pass

def tamper(payload, **kwargs):
   """
   Replaces instances like 'IFNULL(A, B)' with 'CASE WHEN ISNULL(A) THEN (B) ELSE (A) END' counterpart

   Requirement:
       * MySQL
       * SQLite (possibly)
       * SAP MaxDB (possibly)

   Tested against:
       * MySQL 5.0 and 5.5

   Notes:
       * Useful to bypass very weak and bespoke web application firewalls
         that filter the IFNULL() functions

   >>> tamper('IF(,1, 2)')
   'CASE WHEN ISNULL(1) THEN (2) ELSE (1) END'
   """

   if payload and payload.find("IF") > -1:
       while payload.find("IF(") > -1:
           index = payload.find("IF(")
           depth = 1
           comma = []
           end = None

           for i in xrange(index + len("IF("), len(payload)):
               if depth == 1 and payload[i] == ',':
                   comma.append(i)

               elif depth == 1 and payload[i] == ')':
                   end = i
                   break

               elif payload[i] == '(':
                   depth += 1

               elif payload[i] == ')':
                   depth -= 1
           if comma and end:
               _ = payload[index + len("IF("):comma[0]]
               __ = payload[comma[0] + 1:comma[1]]
               ___ = payload[comma[1] + 1:end].lstrip()
               newVal = "CASE WHEN (%s) THEN (%s) ELSE (%s) END" % (_, __, ___)
               payload = payload[:index] + newVal + payload[end + 1:]
           else:
               break

   return payload