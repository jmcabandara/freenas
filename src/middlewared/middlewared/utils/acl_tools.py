# -*- coding=utf-8 -*-
import logging
import os
from bsd import acl

logger = logging.getLogger(__name__)

"""
These are simplified forms of permissions sets based
on NTFS basic permissions. 
"""
TRAVERSE = {
    'READ_DATA': False,
    'WRITE_DATA': False, 
    'APPEND_DATA': False, 
    'READ_NAMED_ATTRS': True, 
    'WRITE_NAMED_ATTRS': False, 
    'EXECUTE': True, 
    'DELETE_CHILD': False, 
    'READ_ATTRIBUTES': True, 
    'WRITE_ATTRIBUTES': False, 
    'DELETE': False, 
    'READ_ACL': True, 
    'WRITE_ACL': False, 
    'WRITE_OWNER': False,
    'SYNCHRONIZE': True 
}
READ = {
    'READ_DATA': True,
    'WRITE_DATA': False, 
    'APPEND_DATA': False, 
    'READ_NAMED_ATTRS': True, 
    'WRITE_NAMED_ATTRS': False, 
    'EXECUTE': True, 
    'DELETE_CHILD': False, 
    'READ_ATTRIBUTES': True, 
    'WRITE_ATTRIBUTES': False, 
    'DELETE': False, 
    'READ_ACL': True, 
    'WRITE_ACL': False,
    'WRITE_OWNER': False,
    'SYNCHRONIZE': True 
}
MODIFY = {
    'READ_DATA': True,
    'WRITE_DATA': True, 
    'APPEND_DATA': True, 
    'READ_NAMED_ATTRS': True, 
    'WRITE_NAMED_ATTRS': True, 
    'EXECUTE': True, 
    'DELETE_CHILD': True, 
    'READ_ATTRIBUTES': True, 
    'WRITE_ATTRIBUTES': True, 
    'DELETE': True, 
    'READ_ACL': True, 
    'WRITE_ACL': False,
    'WRITE_OWNER': False,
    'SYNCHRONIZE': True 
}
FULL_CONTROL = {
    'READ_DATA': True,
    'WRITE_DATA': True, 
    'APPEND_DATA': True, 
    'READ_NAMED_ATTRS': True, 
    'WRITE_NAMED_ATTRS': True, 
    'EXECUTE': True, 
    'DELETE_CHILD': True, 
    'READ_ATTRIBUTES': True, 
    'WRITE_ATTRIBUTES': True, 
    'DELETE': True, 
    'READ_ACL': True, 
    'WRITE_ACL': True,
    'WRITE_OWNER': True,
    'SYNCHRONIZE': True 
}
INHERIT = {
    'FILE_INHERIT': True,
    'DIRECTORY_INHERIT': True,
    'NO_PROPAGATE_INHERIT': False,
    'INHERIT_ONLY': False,
    'INHERITED': False
}

def convert_advanced_simple(permset):
    if permset == FULL_CONTROL:
        return "FULL_CONTROL"
    elif permset == MODIFY:
        return "MODIFY"
    elif permset == READ:
        return "READ"
    elif permset == TRAVERSE:
        return "TRAVERSE"
    elif permset == INHERIT:
        return "INHERIT"
    else:
        return "SPECIAL"


def convert_simple_advanced(permset):
    if permset == "FULL_CONTROL":
        return FULL_CONTROL
    elif permset == "MODIFY":
        return MODIFY
    elif permset == "READ":
        return READ
    elif permset == "TRAVERSE":
        return TRAVERSE
    elif permset == "INHERIT":
        return INHERIT
    else:
        return None
