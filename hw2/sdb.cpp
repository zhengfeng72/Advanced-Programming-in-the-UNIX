#include <stdio.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <elf.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <algorithm>

#include <capstone/capstone.h>

#include "ptools.h"

#include <utility>
#include <map>
#include <string>
#include <vector>

using namespace std;

#define    PEEKSIZE    8

class instruction1 {
public:
    unsigned char bytes[16];
    int size;
    string opr, opnd;
};

static csh cshandle = 0;
static map<long long, instruction1> instructions;
static vector<unsigned long long> instructions_addess;
static pair<unsigned long long, unsigned long long> program_section;


void errquit(const char *msg) {
    perror(msg);
    exit(-1);
}

unsigned long long get_break_address(string command){
    vector<string> result;
    stringstream ss(command);
    string tok;
    string hex_addr;
    unsigned long long break_addr;

    while (getline(ss, tok, ' ')) {
        result.push_back(tok);
    }

    hex_addr = result[1].erase(0,2);
    break_addr = stoul(hex_addr, nullptr, 16);
    // cout << break_addr << endl;
    return break_addr;
}

void
print_instruction(long long addr, instruction1 *in) {
    int i;
    char bytes[128] = "";
    if(in == NULL) {
        fprintf(stderr, "0x%llx:\t<cannot disassemble>\n", addr);
    } else {
        for(i = 0; i < in->size; i++) {
            snprintf(&bytes[i*3], 4, "%2.2x ", in->bytes[i]);
        } 
        // printf("byte: %s\n", bytes);
        fprintf(stderr, "\t0x%llx: %-32s\t%-10s%s\n", addr, bytes, in->opr.c_str(), in->opnd.c_str());
    }
}

void
disassemble(pid_t proc, unsigned long long rip) {
    int count;
    char buf[10000] = { 0 };
    unsigned long long ptr = rip;
    cs_insn *insn;
    map<long long, instruction1>::iterator mi; // from memory addr to instruction
    vector<unsigned long long>::iterator vi;
    int dist_to_end = 0;
    int print_instruction_num = 5;

    vi = find(instructions_addess.begin(), instructions_addess.end(), rip);
    dist_to_end = distance(vi, instructions_addess.end());
    
    if(dist_to_end >= 5){
        for(int i=0; i<print_instruction_num; i++){
            if(*(vi+i) >= program_section.second){
                // printf("** the address is out of the range of the text section. %llx\n", *(vi+i) );
                printf("** the address is out of the range of the text section.\n");
                break;
            }
            if((mi = instructions.find(*(vi+i))) != instructions.end()) {
                print_instruction(*(vi+i), &mi->second);
            }
        }
        return;
    }

    // if((mi = instructions.find(rip)) != instructions.end()) {
    //     print_instruction(rip, &mi->second);
    //     return;
    // }

    for(ptr = rip; ptr < program_section.second; ptr += PEEKSIZE) {
        long long peek;
        errno = 0;
        peek = ptrace(PTRACE_PEEKTEXT, proc, ptr, NULL);
        if(errno != 0) break;
        memcpy(&buf[ptr-rip], &peek, PEEKSIZE);

        // printf("0x%llx\n", ptr);
    }

    if(ptr == rip)  {
        printf("** the address is out of the range of the text section.\n");
        // print_instruction(rip, NULL);
        return;
    }

    if((count = cs_disasm(cshandle, (uint8_t*) buf, rip-ptr, rip, 0, &insn)) > 0) {
        int i;
        for(i = 0; i < count; i++) {
            instruction1 in;
            in.size = insn[i].size;
            in.opr  = insn[i].mnemonic;
            in.opnd = insn[i].op_str;
            memcpy(in.bytes, insn[i].bytes, insn[i].size);
            instructions[insn[i].address] = in;

            instructions_addess.push_back(insn[i].address);
        }
        cs_free(insn, count);
    }

    vi = find(instructions_addess.begin(), instructions_addess.end(), rip);
    dist_to_end = distance(vi, instructions_addess.end());
    print_instruction_num = dist_to_end>=5 ?5 :dist_to_end;

    for(int i=0; i<print_instruction_num; i++){
        if(*(vi+i) >= program_section.second){
            printf("** the address is out of the range of the text section.\n");
            break;
        }

        if((mi = instructions.find(*(vi+i))) != instructions.end()) {
            print_instruction(*(vi+i), &mi->second);
        }
    }

    return;
}

void dump_code(long addr, long code) {
    fprintf(stderr, "## %lx: code = %02x %02x %02x %02x %02x %02x %02x %02x\n",
        addr,
        ((unsigned char *) (&code))[0],
        ((unsigned char *) (&code))[1],
        ((unsigned char *) (&code))[2],
        ((unsigned char *) (&code))[3],
        ((unsigned char *) (&code))[4],
        ((unsigned char *) (&code))[5],
        ((unsigned char *) (&code))[6],
        ((unsigned char *) (&code))[7]);
}

int meet_break_point(unsigned long long rip, map<unsigned long long, unsigned long> break_points){
    map<unsigned long long, unsigned long>::iterator mi;
    if((mi = break_points.find(rip)) != break_points.end()) {
        return 1;
    }else{
        return 0;
    }
}

int main(int argc, char* argv[]){
    if(argc < 1){
        printf("need file");
        return -1;
    }

    int fd;
    Elf64_Ehdr ehdr;
    Elf64_Shdr shdr;

    unsigned long long ret = 0,size=0;
    // Open the ELF file
    fd = open(argv[1], O_RDONLY); 
    if (fd < 0) {
        perror("open");
        return 1;
    }

     // Read the ELF header
    if (read(fd, &ehdr, sizeof(Elf64_Ehdr)) != sizeof(Elf64_Ehdr)) {
        fprintf(stderr, "Failed to read ELF header\n");
        close(fd);
        return 1;
    }

    // Verify ELF identification and class
    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0 || ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
        fprintf(stderr, "Invalid ELF format\n");
        close(fd);
        return 1;
    }

    // Print the entry point
    // printf("Entry Point: 0x%llx\n", (unsigned long long)ehdr.e_entry);

    // Find the text section header
    if (lseek(fd, ehdr.e_shoff + ehdr.e_shentsize * ehdr.e_shstrndx, SEEK_SET) == -1) {
        perror("lseek");
        close(fd);
        return 1;
    }
    if (read(fd, &shdr, sizeof(Elf64_Shdr)) != sizeof(Elf64_Shdr)) {
        fprintf(stderr, "Failed to read section header\n");
        close(fd);
        return 1;
    }


    char *section_names = (char*)malloc(shdr.sh_size);
    // Find the text section size
    if (lseek(fd, shdr.sh_offset, SEEK_SET) == -1) {
        perror("lseek");
        close(fd);
        return 1;
    }
    if (read(fd, section_names, shdr.sh_size) != shdr.sh_size) {
        fprintf(stderr, "Failed to read section names\n");
        free(section_names);
        close(fd);
        return  1;
    }

    if (lseek(fd, ehdr.e_shoff, SEEK_SET) == -1) {
        perror("lseek");
        close(fd);
        return 1;
    }
    for (int i = 0; i < ehdr.e_shnum; ++i) {
        if (read(fd, &shdr, sizeof(Elf64_Shdr)) != sizeof(Elf64_Shdr)) {
            fprintf(stderr, "Failed to read section header\n");
            free(section_names);
            close(fd);
            return 1;
        }

        if (shdr.sh_type == SHT_PROGBITS && shdr.sh_flags == (SHF_ALLOC | SHF_EXECINSTR)) {
            ret = shdr.sh_addr;
            size = shdr.sh_size;
            break;
        }
    }


    // printf("Entry Point: 0x%llx\n", (unsigned long long)(ret));
    // printf("Exit Point: 0x%llx\n", (unsigned long long)(ret + size));

    program_section.first = ret;
    program_section.second = ret + size;
    // Close the file descriptor
    close(fd);

    pid_t child;

    if((child = fork()) < 0) printf("fork");
    if(child == 0) {
        if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) printf("ptrace@child");
        
        execvp(argv[1], argv+1);

        // execlp("./sample1", "./sample1", NULL);
        // printf("execvp");
    } else {
        int wait_status;
        // int counter = 0;
        vector<unsigned long long>::iterator bi;
        map<range_t, map_entry_t> m;
        map<range_t, map_entry_t>::iterator mi;

        map<unsigned long long, unsigned long>break_points;
        map<unsigned long long, unsigned long>anchor_break_points;

        vector<range_t> map_range;
        vector<vector<long long>> anchor_content;

        if(waitpid(child, &wait_status, 0) < 0) printf("waitpid");
        ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);

        // if(load_maps(child, m) > 0) {
        //     for(mi = m.begin(); mi != m.end(); mi++) {
        //         fprintf(stderr, "## %lx-%lx %04o %s\n",
        //             mi->second.range.begin, mi->second.range.end,
        //             mi->second.perm, mi->second.name.c_str());
        //     }
        //     fprintf(stderr, "## %zu map entries loaded.\n", m.size());
        // }

        struct user_regs_struct regs;
        struct user_regs_struct anchor_regs;
        // long ret;
        // unsigned char *ptr = (unsigned char *)&ret;
        unsigned long code;
        string command;
        int is_meet_bp;
        if(WIFSTOPPED(wait_status) > 0) {
            instructions_addess.clear();
            
            printf("** program '%s' loaded. entry point 0x%llx\n", argv[1], program_section.first);
            // printf("program: 0x%llx 0x%llx\n", program_section.first, program_section.second);

            if(cs_open(CS_ARCH_X86, CS_MODE_64, &cshandle) != CS_ERR_OK)
                return -1;

            if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0)
                errquit("ptrace(GETREGS)");


            if(ptrace(PTRACE_GETREGS, child, 0, &regs) == 0) {
                //fprintf(stderr, "0x%llx\n", regs.rip);
                range_t r = { regs.rip, regs.rip };
                mi = m.find(r);
                if(mi == m.end()) {
                    m.clear();
                    // printf("load map\n");
                    load_maps(child, m, map_range);
                    // fprintf(stderr, "## %zu map entries re-loaded.\n", m.size());
                    mi = m.find(r);
                }
                disassemble(child, regs.rip);
            }else{
                cs_close(&cshandle);
            }
        }


        while (WIFSTOPPED(wait_status) > 0) {
            // printf("counter %d\n", counter++);
            // if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) errquit("ptrace@getregs");
            // bi = find(break_points.begin(), break_points.end(), regs.rip);
            // if(bi != break_points.end()) {
            //     printf("** hit a breakpoint at 0x%llx", *bi);
            // }

            // printf("\n\nrip 0x%llx \n", regs.rip);
            printf("(sdb) ");
            getline(cin, command);

            

            if(command == "cont"){
                if(ptrace(PTRACE_SINGLESTEP, child, 0, 0)<0) errquit("ptrace@si");
                if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");

                map<unsigned long long, unsigned long>::iterator iter;
                for(iter = break_points.begin(); iter != break_points.end(); iter++){
                    // printf("set bps 0x%llx\n", iter->first);
                    if(ptrace(PTRACE_POKETEXT, child, iter->first, (iter->second & 0xffffffffffffff00) | 0xcc) != 0) errquit("ptrace@poketext");
                }

                if(ptrace(PTRACE_CONT, child, 0, 0)< 0)  errquit("ptrace@cont");
                if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");

                if(ptrace(PTRACE_GETREGS, child, 0, &regs) == 0){
                    is_meet_bp = meet_break_point(regs.rip-1, break_points);
                    // printf("rip-1 0x%llx\n", regs.rip-1);
                    if(is_meet_bp) {
                        printf("** hit a breakpoint at 0x%llx. \n", regs.rip-1);
                        if(ptrace(PTRACE_POKETEXT, child, regs.rip-1, break_points[regs.rip-1]) != 0) errquit("ptrace@poketext");

                        regs.rip= regs.rip-1;
                        if(ptrace(PTRACE_SETREGS, child, 0, &regs)!=0) errquit("ptrace@setregs");
                    }

                    disassemble(child, regs.rip);
                }

            }else if(command == "si"){
                if(ptrace(PTRACE_SINGLESTEP, child, 0, 0)<0) errquit("ptrace@si");
                if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");

                if(ptrace(PTRACE_GETREGS, child, 0, &regs) == 0){
                    is_meet_bp = meet_break_point(regs.rip, break_points);
                    if(is_meet_bp) {
                        printf("** hit a breakpoint at 0x%llx. \n", regs.rip);
                        if(ptrace(PTRACE_POKETEXT, child, regs.rip, break_points[regs.rip]) != 0) errquit("ptrace@poketext");
                    }
                    disassemble(child, regs.rip);
                }

            }else if(command == "anchor"){
                if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) errquit("ptrace@getreg");
                printf("** dropped an anchor\n");
                anchor_regs = regs;
                anchor_break_points = break_points;
                for(int i=0; i<map_range.size(); i++){
                    range_t mr = map_range[i];
                    vector<long long> anchor_entry; 
                    for(unsigned long long j = mr.begin; j<mr.end; j+=PEEKSIZE){
                        code = ptrace(PTRACE_PEEKDATA, child, j, 0);
                        anchor_entry.push_back(code);
                    }
                    anchor_content.push_back(anchor_entry);
                }

            }else if(command == "timetravel"){
                printf("** go back to the anchor point\n");
                if(ptrace(PTRACE_SETREGS, child, 0, &anchor_regs)!=0) errquit("ptrace@setregs");

                // break_points = anchor_break_points;
                map<unsigned long long, unsigned long>::iterator iter;
                for(iter = break_points.begin(); iter != break_points.end(); iter++){
                    // printf("set bps 0x%llx\n", iter->first);
                    if(ptrace(PTRACE_POKETEXT, child, iter->first, (iter->second & 0xffffffffffffff00) | 0xcc) != 0) errquit("ptrace@poketext");
                }
                if(ptrace(PTRACE_GETREGS, child, 0, &regs) == 0){
                    is_meet_bp = meet_break_point(regs.rip, break_points);
                    if(is_meet_bp) {
                        if(ptrace(PTRACE_POKETEXT, child, regs.rip, break_points[regs.rip]) != 0) errquit("ptrace@poketext");
                    }
                }

                for(int i=0; i<map_range.size(); i++){
                    range_t mr = map_range[i];
                    int count = 0;
                    for(unsigned long long j = mr.begin; j<mr.end; j+=PEEKSIZE){
                        // printf("%d %llx\n",i , anchor_content[i][count++]);
                        if(ptrace(PTRACE_POKEDATA, child, j, anchor_content[i][count++]) != 0 ) errquit("ptrace@poketext@map");
                    }
                }

                if(ptrace(PTRACE_GETREGS, child, 0, &regs) == 0){
                    disassemble(child, regs.rip);
                }

            }else if(command.substr(0,5) == "break"){
                unsigned long long break_address = get_break_address(command);
                code = ptrace(PTRACE_PEEKTEXT, child, break_address, 0);

                break_points[break_address] = code;

                if(ptrace(PTRACE_POKETEXT, child, break_address, (code & 0xffffffffffffff00) | 0xcc) != 0) errquit("ptrace@poketext");


                if(ptrace(PTRACE_GETREGS, child, 0, &regs) == 0){
                    is_meet_bp = meet_break_point(regs.rip, break_points);
                    if(is_meet_bp) {
                        if(ptrace(PTRACE_POKETEXT, child, regs.rip, break_points[regs.rip]) != 0) errquit("ptrace@poketext");
                    }
                }
                // break_points.push_back(break_address);
                printf("** set a breakpoint at 0x%llx\n", break_address);
                // code = ptrace(PTRACE_PEEKTEXT, child, 0x401004, 0);
                // dump_code(0x401004, code);
            }

            // if(ptrace(PTRACE_SINGLESTEP, child, 0, 0) < 0) {
            //     perror("ptrace");
            //     cs_close(&cshandle);
            //     return -2;
            // }

            // ptrace(PTRACE_CONT, child, 0, 0);
            // if(waitpid(child, &wait_status, 0) < 0) printf("waitpid");
        }


        cs_close(&cshandle);
        printf("** the target program terminated.\n");
    }

    return 0;
}