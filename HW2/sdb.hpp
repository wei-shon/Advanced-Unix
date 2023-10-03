# include <iostream>
# include <string>
# include <vector>
#include <sys/ptrace.h>
#include <capstone/capstone.h>
#include <iomanip>

#ifndef __PTOOLS_H__
#define __PTOOLS_H__

#include <sys/types.h>
#include <map>
#include <string>

typedef struct range_s {
	unsigned long begin, end;
}	range_t;

typedef struct map_entry_s {
	range_t range;
	int perm;
	long offset;
	std::string name;
}	map_entry_t;

bool operator<(range_t r1, range_t r2);
int load_maps(pid_t pid, std::map<range_t, map_entry_t>& loaded);

#endif /* __PTOOLS_H__ */


using namespace std;

#define MAXASM  0x100

struct memory_content {
    long long start_addr;
    long data;
    memory_content(long long _a = 0, long _o = 0 )
        : start_addr(_a), data(_o) {
        }
};

struct breakpoint {
    long long addr;
    long data;
    bool flag;
    breakpoint(long long _a = 0, long _o = '\0' , bool _f = false)
        : addr(_a), data(_o) ,flag(_f) {
        }
};

vector<string> splitString(string str, char splitter){
    vector<string> result;
    string current = ""; 
    for(unsigned int i = 0; i < str.size(); i++){
        if(str[i] == splitter){
            if(current != ""){
                result.push_back(current);
                current = "";
            } 
            continue;
        }
        if(str[i] != '\n') current += str[i];
    }
    if(current.size() != 0)
        result.push_back(current);
    return result;
}


long long str2ll(const string &s) {
    if (s.find("0x") == 0 || s.find("0X") == 0) {
        return stoll(s, NULL, 16);
    }
    else if (s.find("0") == 0) {
        return stoll(s, NULL, 8);
    }
    else {
        return stoll(s);
    }
}


string get_byte(const unsigned char *byte) {
    stringstream ss;
    ss << hex << setfill('0') << setw(2) << (int) *byte;
    string tmp;
    ss >> tmp;
    return tmp;
}

string get_bytes(const unsigned char *bytes, int n) {
    string out = "";
    bool fir = true;
    for (int i = 0; i < n; i++) {
        if (!fir) out += " ";
        fir = false;
        out += get_byte(bytes + i);
    }
    return out;
}


