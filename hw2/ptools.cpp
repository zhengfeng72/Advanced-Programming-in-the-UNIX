#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <libgen.h>
#include "ptools.h"

#include <map>
#include <vector>
using namespace std;

bool operator<(range_t r1, range_t r2) {
	if(r1.begin < r2.begin && r1.end < r2.end) return true;
	return false;
}

int
load_maps(pid_t pid, map<range_t, map_entry_t>& loaded, vector<range_t>& map_range) {
	char fn[128];
	char rp[128];
	char buf[256];
	char exe_name[128];
	FILE *fp;
	snprintf(fn, sizeof(fn), "/proc/%u/maps", pid);

	snprintf(rp, sizeof(rp), "/proc/%u/exe", pid);
	if (realpath(rp, exe_name) == NULL)  perror("realpath");

	if((fp = fopen(fn, "rt")) == NULL) return -1;
	while(fgets(buf, sizeof(buf), fp) != NULL) {
		
		int nargs = 0;
		char *token, *saveptr, *args[8], *ptr = buf;
		map_entry_t m;
		while(nargs < 8 && (token = strtok_r(ptr, " \t\n\r", &saveptr)) != NULL) {
			// printf("token %s\n", token);
			args[nargs++] = token;
			ptr = NULL;
		}
		//args
		//00400000-00401000 r-xp 00000000 00:8c 57406863 /shared/lab/hw2/hello64
		//00600000-00601000 rw-p 00000000 00:8c 57406863 /shared/lab/hw2/hello64
		//7fffbfd26000-7fffbfd47000 rw-p 00000000 00:00 0 [stack]
		//7fffbfd87000-7fffbfd8b000 r--p 00000000 00:00 0 [vvar]
		//7fffbfd8b000-7fffbfd8d000 r-xp 00000000 00:00 0 [vdso]
		//ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0 [vsyscall]
		if(nargs < 6) continue;
		if((ptr = strchr(args[0], '-')) != NULL) {
			*ptr = '\0'; // 00600000-00601000 -> 00600000 \0 00601000
			m.range.begin = strtol(args[0], NULL, 16);
			m.range.end = strtol(ptr+1, NULL, 16);
		}
		m.name = basename(args[5]); //hello64
		m.perm = 0;
		if(args[1][0] == 'r') m.perm |= 0x04;
		if(args[1][1] == 'w') m.perm |= 0x02;
		if(args[1][2] == 'x') m.perm |= 0x01;
		m.offset = strtol(args[2], NULL, 16);
		// printf("XXX: %lx-%lx %04o %s\n", m.range.begin, m.range.end, m.perm, m.name.c_str());
		loaded[m.range] = m;

		if (realpath(rp, exe_name) == NULL) perror("realpath");
		if(!strcmp(exe_name,args[5]) && strlen(exe_name)==strlen(args[5])){
			map_range.push_back(m.range);
		}
		if(m.name=="[stack]"){
			map_range.push_back(m.range);
		}
	}
	// for(auto i: map_range){
	// 	printf("%lx %lx\n",i.begin, i.end);
	// }
	return (int) loaded.size();
}

