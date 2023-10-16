#include <sys/ptrace.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/user.h>
#include <stdint.h>
#include <stddef.h>

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
        int wait_status;
        int counter = 0;
        int idx = 0;
        unsigned long long int magic_rax;
        unsigned long long int go_back_rip;
        int isGet = 0;
        if(waitpid(child, &wait_status, 0) < 0) printf("waitpid");
        ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);


        while (WIFSTOPPED(wait_status) > 0) {
            unsigned long long int rax;
            long ret;
            unsigned char *ptr = (unsigned char *)&ret;
            unsigned long code;
            struct user_regs_struct regs;
            if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0)
                printf("ptrace(GETREGS)");

            counter++;
            if (idx > 1023) break;
            // printf("0x%llx counter %d\n", regs.rip, counter);


            if(isGet == 0){
                if(counter == 3){
                    // printf("0x%llx counter %d\n", regs.rip, counter);
                    magic_rax = regs.rax;
                    // printf("%08llx", rip);

                    // printf("\tmagic_rax: [%llx]\n", magic_rax);
                    // go_back_rip = regs.rip;
                    // printf("\tgo_back_rip: [%llx]\n", go_back_rip);
                }

                if(counter == 4){

                    // printf("0x%llx counter %d\n", regs.rip, counter);
                    go_back_rip = regs.rip;
                    isGet=1;
                    counter = 0;
                    
                    continue;
                } 

                ptrace(PTRACE_CONT, child, 0, 0);
                if(waitpid(child, &wait_status, 0) < 0) printf("waitpid");
            }else{
                if(counter == 1 ){
                    // printf("0x%llx counter %d\n", regs.rip, counter);
                    // printf("======= %d ===========\n", idx);
                    // printf("\t rip %llx\n", regs.rip);
                    // ret = ptrace(PTRACE_PEEKTEXT, child, rax, 0);
                    // fprintf(stderr, "0x%llx: %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x\n",
                    //     rax,
                    //     ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5], ptr[6], ptr[7]);

                    if(ptrace(PTRACE_POKETEXT, child ,magic_rax, n_upper_part[idx])!=0) printf("ptrace(PTRACE_POKETEXT)");
                    ret = ptrace(PTRACE_PEEKTEXT, child, magic_rax, 0);
                    // fprintf(stderr, "\t0x%llx: %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x\n",
                    //     magic_rax,
                    //     ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5], ptr[6], ptr[7]);

                    if(ptrace(PTRACE_POKETEXT, child ,magic_rax+8, n_lower_part[idx])!=0) printf("ptrace(PTRACE_POKETEXT)");
                    ret = ptrace(PTRACE_PEEKTEXT, child, magic_rax+8, 0);
                    // fprintf(stderr, "\t0x%llx: %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x\n",
                    //     magic_rax+8,
                    //     ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5], ptr[6], ptr[7]);

                    // printf("%d %lld %d\n", idx, n_upper_part[idx], n_lower_part[idx]);

                }

                ptrace(PTRACE_CONT, child, 0, 0);
                if(waitpid(child, &wait_status, 0) < 0) printf("waitpid");
                // counter++;
                // ptrace(PTRACE_CONT, child, 0, 0);
                // if(waitpid(child, &wait_status, 0) < 0) printf("waitpid");

                if(counter == 3){

                    // printf("0x%llx counter %d\n", regs.rip, counter);
                    rax = regs.rax;
                    // printf("\trax: [%llx]\n", rax);
                    if(rax == 0) {
                        break;
                    }else{
                        regs.rip = go_back_rip;
                        idx++;
                        counter = 0;
                        if(ptrace(PTRACE_SETREGS, child, 0, &regs) != 0) printf("ptrace(PTRACE_SETREGS)");

                        // ptrace(PTRACE_SINGLESTEP, child, 0, 0);
                        // if(waitpid(child, &wait_status, 0) < 0) printf("waitpid");
                        // // printf("\tjump to %llx  \n\n" ,regs.rip);
                        // continue;
                    }
                }
                
            }
        }
    }
}