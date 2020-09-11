#!/usr/bin/env python3

from sys import argv
from struct import pack, unpack
from enum import Enum
from os import listdir

class ImageDataDirectory(Enum):
    IMAGE_DIRECTORY_ENTRY_EXPORT = 0,
    IMAGE_DIRECTORY_ENTRY_IMPORT = 1,
    IMAGE_DIRECTORY_ENTRY_RESOURCE = 2,
    IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3,
    IMAGE_DIRECTORY_ENTRY_SECURITY = 4,
    IMAGE_DIRECTORY_ENTRY_BASERELOC = 5,
    IMAGE_DIRECTORY_ENTRY_DEBUG = 6,
    IMAGE_DIRECTORY_ENTRY_ARCHITECTURE = 7,
    IMAGE_DIRECTORY_ENTRY_GLOBALPTR = 8,
    IMAGE_DIRECTORY_ENTRY_TLS = 9,
    IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10,
    IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT = 11,
    IMAGE_DIRECTORY_ENTRY_IAT = 12,
    IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = 13,
    IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14,
    IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 15,


def u64(x): return unpack('<Q', x)[0]
def u32(x): return unpack('<I', x)[0]
def u16(x): return unpack('<H', x)[0]
def u8(x): return unpack('<B', x)[0]
def p64(x): return pack('<Q', x)
def p32(x): return pack('<I', x)
def p16(x): return pack('<H', x)
def p8(x): return pack('<B', x)



class PE(object):
    def __init__(self, fname):
        self.fp = open(fname, 'rb')
        assert(self.fp.read(2) == b'MZ')

        rsrc = self.image_data_directory(ImageDataDirectory.IMAGE_DIRECTORY_ENTRY_RESOURCE)
        va = u32(rsrc['VirtualAddress'])
        sz = u32(rsrc['Size'])
        fo = self.rva2fo(va)
        self.fp.seek(fo)
        rsrc = self.fp.read(sz)
        if b'n\0t\0d\0l\0l\0.\0d\0l\0l\0\0\0' not in rsrc:
            print('[!] {} is likely not ntdll.dll')
        offset = rsrc.index(b'F\0i\0l\0e\0V\0e\0r\0s\0i\0o\0n\0\0\0\0\0')
        if offset:
            offset += 24
            pad = offset % 4
            if pad:
                offset += 4 - pad
            self.fp.seek(fo + offset)
            self.version = self.w_str()
            print('[!] Windows version: {}'.format(self.version))

    def image_dos_header(self):
        self.fp.seek(0)
        return {
            'e_magic': self.fp.read(2),
            'e_cblp': self.fp.read(2),
            'e_cp': self.fp.read(2),
            'e_crlc': self.fp.read(2),
            'e_cparhdr': self.fp.read(2),
            'e_minalloc': self.fp.read(2),
            'e_maxalloc': self.fp.read(2),
            'e_ss': self.fp.read(2),
            'e_sp': self.fp.read(2),
            'e_csum': self.fp.read(2),
            'e_ip': self.fp.read(2),
            'e_cs': self.fp.read(2),
            'e_lfarlc': self.fp.read(2),
            'e_ovno': self.fp.read(2),
            'e_res': self.fp.read(2),
            '': self.fp.read(2),
            '': self.fp.read(2),
            '': self.fp.read(2),
            'e_oemid': self.fp.read(2),
            'e_oeminfo': self.fp.read(2),
            'e_res2': self.fp.read(2),
            '': self.fp.read(2),
            '': self.fp.read(2),
            '': self.fp.read(2),
            '': self.fp.read(2),
            '': self.fp.read(2),
            '': self.fp.read(2),
            '': self.fp.read(2),
            '': self.fp.read(2),
            '': self.fp.read(2),
            'e_lfanew': self.fp.read(4),            
        }

    def image_file_header(self):
        pos = u32(self.image_dos_header()['e_lfanew']) + 4
        self.fp.seek(pos)
        return {
            'Machine': self.fp.read(2),
            'NumberOfSections': self.fp.read(2),
            'TimeDateStamp': self.fp.read(4),
            'PointerToSymbolTable': self.fp.read(4),
            'NumberOfSymbols': self.fp.read(4),
            'SizeOfOptionalHeader': self.fp.read(2),
            'Characteristics': self.fp.read(2),
        }

    def image_optional_header(self):
        self.image_file_header()
        return {
            'Magic': self.fp.read(2),
            'MajorLinkerVersion': self.fp.read(1),
            'MinorLinkerVersion': self.fp.read(1),
            'SizeOfCode': self.fp.read(4),
            'SizeOfInitializedData': self.fp.read(4),
            'SizeOfUninitializedData': self.fp.read(4),
            'AddressOfEntryPoint': self.fp.read(4),
            'BaseOfCode': self.fp.read(4),
            'ImageBase': self.fp.read(8),
            'SectionAlignment': self.fp.read(4),
            'FileAlignment': self.fp.read(4),
            'MajorOperatingSystemVersion': self.fp.read(2),
            'MinorOperatingSystemVersion': self.fp.read(2),
            'MajorImageVersion': self.fp.read(2),
            'MinorImageVersion': self.fp.read(2),
            'MajorSubsystemVersion': self.fp.read(2),
            'MinorSubsystemVersion': self.fp.read(2),
            'Win32VersionValue': self.fp.read(4),
            'SizeOfImage': self.fp.read(4),
            'SizeOfHeaders': self.fp.read(4),
            'CheckSum': self.fp.read(4),
            'Subsystem': self.fp.read(2),
            'DllCharacteristics': self.fp.read(2),
            'SizeOfStackReserve': self.fp.read(8),
            'SizeOfStackCommit': self.fp.read(8),
            'SizeOfHeapReserve': self.fp.read(8),
            'SizeOfHeapCommit': self.fp.read(8),
            'LoaderFlags': self.fp.read(4),
            'NumberOfRvaAndSizes': self.fp.read(4),
        }
    
    def image_data_directory(self, idx: ImageDataDirectory):
        self.image_optional_header()
        self.fp.seek(idx.value[0] * 8, 1)
        return {
            'VirtualAddress': self.fp.read(4),
            'Size': self.fp.read(4)
        }

    def image_section_header(self, idx):
        SizeOfOptionalHeader = u16(self.image_file_header()['SizeOfOptionalHeader'])
        self.fp.seek(SizeOfOptionalHeader + idx * 40, 1)
        return {
            'Name': self.fp.read(8),
            'VirtualSize': self.fp.read(4),
            'VirtualAddress': self.fp.read(4),
            'SizeOfRawData': self.fp.read(4),
            'PointerToRawData': self.fp.read(4),
            'PointerToRelocations': self.fp.read(4),
            'PointerToLinenumbers': self.fp.read(4),
            'NumberOfRelocations': self.fp.read(2),
            'NumberOfLinenumbers': self.fp.read(2),
            'Characteristics': self.fp.read(4),
        }
    
    def image_export_directory(self):
        directory = self.image_data_directory(ImageDataDirectory.IMAGE_DIRECTORY_ENTRY_EXPORT)
        fo = self.rva2fo(u32(directory['VirtualAddress']))
        sz = u32(directory['Size'])
        self.fp.seek(fo)
        return {
            'Characteristics': self.fp.read(4),
            'TimeDateStamp': self.fp.read(4),
            'MajorVersion': self.fp.read(2),
            'MinorVersion': self.fp.read(2),
            'Name': self.fp.read(4),
            'Base': self.fp.read(4),
            'NumberOfFunctions': self.fp.read(4),
            'NumberOfNames': self.fp.read(4),
            'AddressOfFunctions': self.fp.read(4),
            'AddressOfNames': self.fp.read(4),
            'AddressOfNameOrdinals': self.fp.read(4),
        }

    def rva2fo(self, rva):
        if rva <= u32(self.image_optional_header()['FileAlignment']):
            return rva
        for i in range(u16(self.image_file_header()['NumberOfSections'])):
            section = self.image_section_header(i)
            va = u32(section['VirtualAddress'])
            sz = u32(section['VirtualSize'])
            fo = u32(section['PointerToRawData'])
            if rva >= va and rva < va + sz:
                return rva - va + fo

    def c_str(self):
        result = b''
        c = self.fp.read(1)
        while c != b'\0':
            result += c
            c = self.fp.read(1)
        return result

    def w_str(self):
        result = b''
        c = self.fp.read(2)
        while c != b'\0\0':
            result += bytes([c[0]])
            c = self.fp.read(2)
        return result


def get_syscall_number(data):
    if data[3] == ord(b'\xb8') and data[18:20] == b'\x0f\x05':
        return u32(data[4:8])
    return -1

def get_syscalls():
    ntdll = PE(argv[1])

    exports = ntdll.image_export_directory()

    NumberOfNames = u32(exports['NumberOfNames'])
    AddressOfNames = u32(exports['AddressOfNames'])
    AddressOfFunctions = u32(exports['AddressOfFunctions'])
    AddressOfNameOrdinals = u32(exports['AddressOfNameOrdinals'])

    ntdll.fp.seek(ntdll.rva2fo(AddressOfNames))
    names = ntdll.fp.read(NumberOfNames * 4)
    names = list(map(u32, [names[i:i+4] for i in range(0, len(names), 4)]))

    ntdll.fp.seek(ntdll.rva2fo(AddressOfFunctions))
    functions = ntdll.fp.read(NumberOfNames * 4)
    functions = list(map(u32, [functions[i:i+4] for i in range(0, len(functions), 4)]))

    ntdll.fp.seek(ntdll.rva2fo(AddressOfNameOrdinals))
    ordinals = ntdll.fp.read(NumberOfNames * 2)
    ordinals = list(map(u16, [ordinals[i:i+2] for i in range(0, len(ordinals), 2)]))

    syscalls = {}

    for i, rva in enumerate(names):
        ntdll.fp.seek(ntdll.rva2fo(rva))
        fname = ntdll.c_str()
        if fname.startswith(b'Nt'):
            rva = functions[ordinals[i]]
            ntdll.fp.seek(ntdll.rva2fo(rva))
            data = ntdll.fp.read(24)
            sysnum = get_syscall_number(data)
            if sysnum > -1 and sysnum not in syscalls:
                syscalls[sysnum] = fname.decode()

    return syscalls

def print_syscalls(syscalls):
    for syscall in syscalls:
        print('{:.<60s}: {:#x}'.format(syscalls[syscall], syscall))

def get_definition(api):
    for file in listdir('phnt'):
        if not file.endswith('.h'):
            continue

        data = open(f'phnt/{file}', 'r').read().split('\n')
        if api + '(' not in data:
            continue

        idx = data.index(api + '(')
        params = []

        while True:
            idx += 1
            param = data[idx].split()
            if param[0].endswith(');'):
                break
            if param[0] == 'VOID':
                params.append(f'{param[0]}')
            else:
                ptype = param[-2]
                param = param[-1].strip(',')
                params.append(f'{ptype} {param}')

        return 'typedef NTSTATUS(NTAPI* {}_t)( {} );'.format(api, ', '.join(params))


    print('NTAPI DEFINITION NOT FOUND: {}'.format(api))



def main():

    syscalls = get_syscalls()
    #print_syscalls(syscalls)

    with open('ntdefs.h', 'w') as header:
        for sys in syscalls:
            ntdef = get_definition(syscalls[sys])
            if ntdef:
                header.write(ntdef + '\n')


if __name__ == '__main__':
    if len(argv) != 2:
        print('Usage: {} <ntdll.dll>'.format(argv[0]))
    else:
        main()
