# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
#
# This file is part of Volatility.
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Volatility is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Volatility.  If not, see <http://www.gnu.org/licenses/>.
#
from itertools import count

"""
@author:       Andrew Case
@license:      GNU General Public License 2.0
@contact:      atcuno@gmail.com
"""

import hashlib
import volatility.obj as obj
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.pslist as linux_pslist
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address

# Constants
PAGE_SIZE = 4096 # bytes
ZYGOTE_COMM = "zygote"
NONAME_REGION = "_anonymous_"
VMA_PA_FAIL = 0

VM_R  = 0x00000001 # read
VM_W  = 0x00000002 # write
VM_X  = 0x00000004 # execute
VM_S  = 0x00000080 # shared
VM_IO = 0x00004000 # memory-mapped IO

class linux_proc_maps(linux_pslist.linux_pslist):
    """Gathers process memory maps"""

    def calculate(self):
        linux_common.set_plugin_members(self)
        tasks = linux_pslist.linux_pslist.calculate(self)

        for task in tasks:
            if task.mm:
                for vma in task.get_proc_maps():
                    yield task, vma            

    def unified_output(self, data):
        return TreeGrid([("Offset",Address),
                        ("Pid", int),
                         ("Name",str),
                       ("Start", Address),
                       ("End", Address),
                       ("Flags", str),
                       ("Pgoff", Address),
                       ("Major", int),
                       ("Minor", int),
                       ("Inode", int),
                       ("Path", str)],
                        self.generator(data))

    def generator(self, data):
        for task, vma in data:
            (fname, major, minor, ino, pgoff) = vma.info(task)

            yield (0, [Address(task.obj_offset),
                       int(task.pid),
                       str(task.comm),
                Address(vma.vm_start),
                Address(vma.vm_end),
                str(vma.vm_flags),
                Address(pgoff),
                int(major),
                int(minor),
                int(ino),
                str(fname)])

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Offset","#018x"),
                                  ("Pid", "8"),
                                  ("Name","20"),
                                  ("Start", "#018x"),
                                  ("End",   "#018x"),
                                  ("Flags", "6"),
                                  ("Pgoff", "[addr]"),
                                  ("Major", "6"),
                                  ("Minor", "6"),
                                  ("Inode", "10"),
                                  ("File Path", ""),                    
                                 ]) 
        for task, vma in data:
            (fname, major, minor, ino, pgoff) = vma.info(task)

            self.table_row(outfd, task.obj_offset,
                task.pid,
                task.comm,
                vma.vm_start,
                vma.vm_end,
                str(vma.vm_flags),
                pgoff,
                major,
                minor,
                ino,
                fname)

# Create ksm map
class ResultTable(object):
    def __init__(self):
        self.__memory_region_dict = {}
        
    def add(self, region, hash_value, physical_addr):
        if self.__memory_region_dict.get(region) is None:
            self.__memory_region_dict[region] = MemoryRegion(region)

        self.__memory_region_dict[region].add(hash_value, physical_addr)  
        
    def hashed_contents(self):
        return self.__memory_region_dict.values()  

class MemoryRegion(object):
    def __init__(self, region):
        self.__region = region
        self.__hash_list = []
        self.__physical_addr_list = []
        
    def add(self, hash_value, physical_addr):
        if hash_value not in self.__hash_list:
            self.__hash_list.append(hash_value)
        
        if physical_addr not in self.__physical_addr_list:
            self.__physical_addr_list.append(physical_addr)
    
    def get_memory_region(self):
        return self.__region
    
    def hash_values(self):
        return self.__hash_list[:]
    
    def physical_addresses(self):
        return self.__physical_addr_list[:]
        
class DuplicationTable(object):
    def __init__(self, hash_func=hashlib.md5):
        self.__hashed_content_dict = {}
        self.__hash_func = hash_func

    def add(self, content, physical_addr, pid, comm, virtual_addr, region, flags):
        content_hash = self.__hash_func(content).hexdigest()

        if self.__hashed_content_dict.get(content_hash) is None:
            self.__hashed_content_dict[content_hash] = HashedContent(content_hash)

        self.__hashed_content_dict[content_hash].add(physical_addr, pid, comm, virtual_addr, region, flags)

    def finalize(self):
        for hashed_content in self.hashed_contents():
            if len(hashed_content.physical_pages()) < 2:
                self.__hashed_content_dict.pop(hashed_content.get_hash_value())

    def hashed_contents(self):
        return self.__hashed_content_dict.values()


class HashedContent(object):
    def __init__(self, content_hash):
        self.__content_hash = content_hash
        self.__physical_page_dict = {}

    def add(self, physical_addr, pid, comm, virtual_addr, region, flags):
        if self.__physical_page_dict.get(physical_addr) is None:
            self.__physical_page_dict[physical_addr] = PhysicalPage(physical_addr)

        self.__physical_page_dict[physical_addr].add(pid, comm, virtual_addr, region, flags)

    def physical_pages(self):
        return self.__physical_page_dict.values()

    def get_hash_value(self):
        return self.__content_hash


class PhysicalPage(object):
    def __init__(self, physical_addr):
        self.__physical_addr = physical_addr
        self.__virtual_page_list = []

    def add(self, pid, comm, virtual_addr, region, flags):
        virtual_page = VirtualPage(pid, comm, virtual_addr, region, flags)
        if virtual_page not in self.__virtual_page_list:
            self.__virtual_page_list.append(virtual_page)
        else:
            del virtual_page

    def virtual_pages(self):
        return self.__virtual_page_list[:]

    def get_address(self):
        return self.__physical_addr


class VirtualPage(object):
    def __init__(self, comm, pid, virtual_addr, region, flags):
        self.__comm = comm
        self.__pid = pid
        self.__virtual_addr = virtual_addr
        self.__region = region
        self.__flags = flags

    def __hash__(self):
        return hash('%s %d 0x%08x' % (self.__comm, self.__pid, self.__virtual_addr))

    def __eq__(self, other):
        return (self.__comm == other.__comm) and \
           (self.__pid == other.__pid) and \
           (self.__virtual_addr == other.__virtual_addr)

    def get_pid(self):
        return self.__pid

    def get_comm(self):
        return self.__comm

    def get_address(self):
        return self.__virtual_addr

    def get_region(self):
        return self.__region

    def get_flags(self):
        return self.__flags
    
class linux_ksmmap(linux_pslist.linux_pslist):
    """Gathers process memory maps"""

    def calculate(self):
        linux_common.set_plugin_members(self)
        tasks = linux_pslist.linux_pslist.calculate(self)

        for task in tasks:
            if task.mm:
                for vma in task.get_proc_maps():
                    yield task, vma            

    def unified_output(self, data):
        return TreeGrid([("Hash",Address),
                        ("Pid", int),
                        ("Name",str),
                        ("VA", Address),
                        ("Flags", str),
                        ("PA", Address),
                        ("Path", str)],
                        self.generator(data))

    def generator(self, data):
        for task, vma in data:
            (fname, major, minor, ino, pgoff) = vma.info(task)

            yield (0, [Address(task.obj_offset),
                       int(task.pid),
                       str(task.comm),
                Address(vma.vm_start),
                Address(vma.vm_end),
                str(vma.vm_flags),
                Address(pgoff),
                str(fname)])

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Hash","32"),
                                  ("Pid", "8"),
                                  ("Name","20"),
                                  ("VA", "#018x"),
                                  ("Flags", "6"),
                                  ("PA", "#018x"),
                                  ("File Path", ""),                    
                                 ])
        # build duplication table
        table = self.build_duplication_table(data, hashlib.md5, outfd)
        resultTable = ResultTable()
        
        for hashed_content in table.hashed_contents():
            for physical_page in hashed_content.physical_pages():
                for virtual_page in physical_page.virtual_pages():
                    resultTable.add(virtual_page.get_region(), 
                                    hashed_content.get_hash_value(), 
                                    physical_page.get_address())
        self.print_result_table(resultTable)
        #self.print_table(table)
    
    def build_duplication_table(self, data, hash_func, outfd):
        table = DuplicationTable()
        prev_region = ''
        
        for task, vma in data:
            comm = str(task.comm)
            pid = int(task.pid)
            (fname, major, minor, ino, pgoff) = vma.info(task)
            
            # Debug
            #if pid > 100:
            #    break
            
            # fname is not None it is "", mark anonymous
            region = NONAME_REGION if fname == "" else str(fname)
            vm_start = int(vma.vm_start)
            vm_end = int(vma.vm_end)
            vm_flags = int(vma.vm_flags)
    
            if not (vm_flags & (VM_R | VM_W | VM_X)):
            # skip protection region
                continue
    
            if vm_flags & VM_IO:
            # skip memory-mapped region
                continue
            
            # assume that the very next region of library(.so) region
            # with noname is BSS segment for that library.
            if prev_region.endswith(".so") and region == NONAME_REGION:
                region = prev_region + "(bss)"
    
            prev_region = region
            task_space = task.get_process_address_space()
    
            for vaddr in range(vm_start, vm_end, PAGE_SIZE):
                try:                        
                    paddr = task_space.vtop(vaddr)
                except:
                    # invalid virt-to-phys mapping
                    continue
                
                #strpaddr = VMA_PA_FAIL if paddr is None else paddr
                if paddr is None:
                    continue
                page = task_space.zread(vaddr, PAGE_SIZE)
                table.add(page, paddr, pid, comm, vaddr, region, vm_flags)
                #self.table_row(outfd, hashlib.md5(page).hexdigest(),
                #pid,
                #comm,
                #vaddr,
                #str(vma.vm_flags),
                #paddr,
                #region)
                #outfd.write(hashlib.md5(page).hexdigest())

        table.finalize()
        return table

    def print_result_table(self, table):
        for memory_regions in table.hashed_contents():
            print memory_regions.get_memory_region()
            print len(memory_regions.hash_values())
            print len(memory_regions.physical_addresses())
            print ''

    def print_result_table1(self, table):
        for memory_regions in table.hashed_contents():
            print memory_regions.get_memory_region()
            for hash_value in memory_regions.hash_values():
                print hash_value
            for physical_page in memory_regions.physical_addresses():
                print '\t0x%08x' % physical_page
            print ''

    def print_table(self, table):
        for hashed_content in table.hashed_contents():
            print hashed_content.get_hash_value()
            for physical_page in hashed_content.physical_pages():
                print '\t0x%08x' % physical_page.get_address()
                for virtual_page in physical_page.virtual_pages():
                    print '\t\t%15s\t0x%08x\t%s' % (virtual_page.get_comm(),
                                        virtual_page.get_address(),
                                        virtual_page.get_region())
            print ''
