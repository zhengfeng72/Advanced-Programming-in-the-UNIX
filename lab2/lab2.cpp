#include <iostream>
#include <string>
#include <experimental/filesystem>
#include <fstream>
#include <cstdlib>

using namespace std;
namespace fs = std::experimental::filesystem;
using std::experimental::filesystem::v1::__cxx11::recursive_directory_iterator;


int main(int argc, char *argv[]){
    string dir_name = argv[1];
    string magic = argv[2];
    string res;
    //ifstream indata;
    cerr << dir_name << " " << magic << endl<<endl;
    int num;
    for(const auto& file : recursive_directory_iterator(dir_name)){
        fs::path fpath = file.path();
        //cout << fpath.filename() << endl;
        ifstream ifs(file.path(), ifstream::in);
        string str;
        while(ifs >> str){
            if(str.find(magic)!=string::npos){
                res = string(fpath.parent_path()) + "/" + string(fpath.filename());
                break;
            }
        }

        ifs.close();
    }

    cout << res <<endl;
    return 0;
}