#include <sys/ptrace.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/user.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

long digit_l;
long tmp_l;
long sum_l;
unsigned long long digit_u;
unsigned long long tmp_u;
unsigned long long sum_u;

unsigned long long n_upper_part[1024];
long n_lower_part[1024];


void generateNumbers(int index, char magic[], int size, int* currentIndex) {
    // Base case: if all elements have been processed, store the number in the 'all' array
    if (index == size ) {
        // sprintf(all[*currentIndex], "%s", magic);  // Store the generated number in the 'all' array
        char tmp_up[9];
        char tmp_low[3];
        
        digit_l = 1;
        sum_l = 0;
        
        digit_u = 1;
        sum_u = 0;
        for(int i=0; i<11; i++){
            if(i <= 7){
                tmp_up[i] = magic[i];
            }else{
                tmp_low[i-8] = magic[i];
            }
        }

         for(int j=0; j<2; j++){
            sum_l += (tmp_low[j] * digit_l);
            digit_l *= 256;
        }
        for(int j=0; j<8; j++){
            sum_u += (tmp_up[j] * digit_u);
            digit_u *= 256;
        }

        n_lower_part[*currentIndex] = sum_l;
        n_upper_part[*currentIndex] = sum_u;
        (*currentIndex)++;
        return;
    }

    // Recursive case: try both possibilities ('0' and '1') for the current element
    magic[index] = '0';
    generateNumbers(index + 1, magic, size, currentIndex);

    magic[index] = '1';
    generateNumbers(index + 1, magic, size, currentIndex);
}


int counter = 0;
int wait_status;
void nextCC(pid_t child){
    // printf("%d\n", ++counter);
    ptrace(PTRACE_CONT, child, 0, 0);
    if(waitpid(child, &wait_status, 0) < 0) printf("waitpid");
}

int main(int argc, char *argv[]){
    if(argc < 1){
        printf("need file");
        return -1;
    }

    char magic[10] = { '0' };

    int currentIndex = 0;
    generateNumbers(0, magic, 10, &currentIndex);

    // Print all the stored numbers

    pid_t child;

    if((child = fork()) < 0) printf("fork");
    if(child == 0) {
        if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) printf("ptrace@child");
        
        execvp(argv[1], argv+1);

		// execlp("./sample1", "./sample1", NULL);
        // printf("execvp");
    } else {
        int idx = 0;
        unsigned long long int magic_rax;
        unsigned long long int go_back_rip;
        int isGet = 0;
        if(waitpid(child, &wait_status, 0) < 0) printf("waitpid");
        ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);

            unsigned long long int rax;
            long ret;
            unsigned char *ptr = (unsigned char *)&ret;
            struct user_regs_struct regs;

            nextCC(child);
            nextCC(child);
            if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) printf("ptrace(GETREGS)");
            magic_rax = regs.rax;

            nextCC(child);
            if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) printf("ptrace(GETREGS)");
            go_back_rip = regs.rip;

            for(int i=0; i<1024; i++){
                // if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) printf("ptrace(GETREGS)");
                // rax = regs.rax;
                // printf("%llx\n", rax);
                if(ptrace(PTRACE_POKETEXT, child ,magic_rax, n_upper_part[i])!=0) printf("ptrace(PTRACE_POKETEXT)");
                ret = ptrace(PTRACE_PEEKTEXT, child, magic_rax, 0);
                // fprintf(stderr, "\t0x%llx: %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x\n",
                //         magic_rax,
                //         ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5], ptr[6], ptr[7]);

                if(ptrace(PTRACE_POKETEXT, child ,magic_rax+8, n_lower_part[i])!=0) printf("ptrace(PTRACE_POKETEXT)");
                ret = ptrace(PTRACE_PEEKTEXT, child, magic_rax+8, 0);
                // fprintf(stderr, "\t0x%llx: %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x\n",
                //         magic_rax,
                //         ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5], ptr[6], ptr[7]);
                nextCC(child);
                nextCC(child);
                if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) printf("ptrace(GETREGS)");
                rax = regs.rax;
                if(rax == 0) {
                    // nextCC(child);
                    break;
                }else{
                    regs.rip = go_back_rip;
                    if(ptrace(PTRACE_SETREGS, child, 0, &regs) != 0) printf("ptrace(PTRACE_SETREGS)");
                    // if(ptrace(PTRACE_SINGLESTEP, child, 0, &regs) != 0) printf("ptrace(SINGLESTEP)");
                }
            }
        }


        // while (WIFSTOPPED(wait_status) > 0) {
        //     unsigned long long int rax;
        //     long ret;
        //     unsigned char *ptr = (unsigned char *)&ret;
        //     struct user_regs_struct regs;

        //     if(isGet == 0){
        //         nextCC(child);
        //         nextCC(child);
        //         if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) printf("ptrace(GETREGS)");
        //         magic_rax = regs.rax;

        //         nextCC(child);
        //         if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) printf("ptrace(GETREGS)");
        //         go_back_rip = regs.rip;
        //         isGet=1;
        //     }else{
        //         // if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) printf("ptrace(GETREGS)");
        //         // rax = regs.rax;
        //         // printf("%llx\n", rax);
        //         if(ptrace(PTRACE_POKETEXT, child ,magic_rax, n_upper_part[idx])!=0) printf("ptrace(PTRACE_POKETEXT)");
        //         ret = ptrace(PTRACE_PEEKTEXT, child, magic_rax, 0);
        //         // fprintf(stderr, "\t0x%llx: %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x\n",
        //         //         magic_rax,
        //         //         ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5], ptr[6], ptr[7]);

        //         if(ptrace(PTRACE_POKETEXT, child ,magic_rax+8, n_lower_part[idx])!=0) printf("ptrace(PTRACE_POKETEXT)");
        //         ret = ptrace(PTRACE_PEEKTEXT, child, magic_rax+8, 0);
        //         // fprintf(stderr, "\t0x%llx: %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x\n",
        //         //         magic_rax,
        //         //         ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5], ptr[6], ptr[7]);
        //         idx++;
        //         nextCC(child);
        //         nextCC(child);
        //         if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) printf("ptrace(GETREGS)");
        //         rax = regs.rax;
        //         if(rax == 0) {
        //             // nextCC(child);
        //         }else{
        //             regs.rip = go_back_rip;
        //             if(ptrace(PTRACE_SETREGS, child, 0, &regs) != 0) printf("ptrace(PTRACE_SETREGS)");
        //             // if(ptrace(PTRACE_SINGLESTEP, child, 0, &regs) != 0) printf("ptrace(SINGLESTEP)");
        //         }
        //     }
        // }
}