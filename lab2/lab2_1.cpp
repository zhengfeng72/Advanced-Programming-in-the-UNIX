#include<iostream>
#include<dirent.h>
#include<errno.h>
#include<string>
#include<fstream>
#include<sys/stat.h>

using namespace std;
string res = "";

void ReadFile(string file_name, string goal){
    ifstream fin(file_name);
    string sin;
    while(getline(fin, sin)){
        if(sin.find(goal) != string::npos){
            res = file_name;
            return;
        }
    }
}

void GetFiles(string path, string goal){
    DIR* dir;
    if((dir = opendir(path.c_str())) == nullptr){
        perror("File path does not exist");
    }
    struct dirent* dp;
    struct stat filestat;
    for(dp = readdir(dir); dp != nullptr; dp = readdir(dir)){
        string full_path = path + '/' + string(dp->d_name);
        lstat(full_path.c_str(), &filestat);
        if((filestat.st_mode & S_IFMT) == S_IFREG){
            ReadFile(full_path, goal);
            if(res.size() != 0){
                return;
            }
        }
        if((filestat.st_mode & S_IFMT) == S_IFDIR){
            if(string(dp->d_name) == "." || string(dp->d_name) == ".."){
                continue;
            }
            // cout<<"DIR : "<<dp->d_name<<endl;
            string dir_path = path + '/' + string(dp->d_name);
            GetFiles(dir_path, goal);
        }
    }
}

int main(int argc, char* argv[]){
    string path = string(argv[1]);
    string goal = string(argv[2]);
    GetFiles(path, goal);
    cout<<res<<endl;
    return 0;
}