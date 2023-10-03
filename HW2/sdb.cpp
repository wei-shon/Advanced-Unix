# include <iostream>
# include <stdio.h>
#include <string.h>
# include <string>
# include <vector>
#include <sys/ptrace.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fstream>
#include <sys/user.h>
#include <fcntl.h>
#include "sdb.hpp"
#include "elf.hpp"
#include <sys/types.h>
#include <libgen.h>
#include <map>
using namespace std;




void launch();
void load();
int load_text_content();
void Disassemble();
void Continue();
void BreakPoint(long long addr);
void StepInstruction();
void Anchor();
void Timetravel();
void load_mem();

void get_code() ;
string get_mem(const long long addr) ;
bool isintext(const long long addr) ;
int chkst(int code) ;
bool operator<(range_t r1, range_t r2);
int load_maps(pid_t pid, map<range_t, map_entry_t>& loaded);

string file_name;
elf_handle_t *eh = NULL;
elf_strtab_t *tab = NULL;
elf_shdr_t texts = {0};
elf_phdr_t tphdr = {0};
pid_t child = 0;
int hitbp;
char *code_context = NULL;
long long Program_Start_Addr = -1;
long long Current_Addr = -1;
long long Last_Addr = -1;
bool hit_bp_restore_CC = false;
vector<breakpoint> bpoints;
struct user_regs_struct recent_regs ;
struct user_regs_struct anchor_regs ;
map<range_t, map_entry_t> mem;
bool anchor_exist = false;
vector <memory_content> mem_content;
char *text_content =NULL;
int mem_size = 0;
long int basic_address;


int main( int argc , char* argv[]){

    if(argc < 2){
        cerr<<"You loss the program name"<<endl;
        return -1;
    }
    file_name = argv[1];
    // Launch Program
    launch();
    Disassemble();
    while(true){
        cout<<"(sdb) ";
        // Get the command line
        string all_command = "";
        getline(cin,all_command);
        vector<string> Input_command = splitString(all_command , ' ');
        string command = Input_command[0];

        // Execute the command
        if(command == "cont" || command == "c"){
            Continue();
        }
        else if(command == "si" || command =="s"){
            StepInstruction();
        }
        else if(command == "b" || command == "break"){
            if(command.size() < 1){
                cerr << "Please give me the break address!!!!"<<endl;
                return -1;
            }
            // string address = Input_command[1].substr(2);
            long long addr  = str2ll(Input_command[1]);
            // cout << addr<<endl;
            BreakPoint( addr);
        }
        else if(command == "anchor" || command == "a"){
            Anchor();
        }
        else if(command == "timetravel" || command == "t" ){
            Timetravel();
            Disassemble();
        }
        else if(command == "exit" ){
            break;
        }
        else{
            cerr << "invalid command!!"<<endl;
            cerr << "Command is list below : "<<endl;
            cerr << "       Continue : [cont] or [c] "<<endl;
            cerr << "       Break : [break] or [b] "<<endl;
            cerr << "       Step Instruction : [si] "<<endl;
            cerr << "       Time Travel store register : [anchor] "<<endl;
            cerr << "       Time Travel go back to previous time : [timetravel] "<<endl;
        }
        Input_command.clear();
    }
    return 0;
}

bool isintext(const long long addr) {
    return texts.addr <= addr && addr <= (texts.addr + texts.size);
}

string get_mem(const long long addr) {
    string s = "";
    for (int i = 0; i < MAXASM / 8; i++) {
        auto out = ptrace(PTRACE_PEEKTEXT, child, addr, NULL);
        s += string((char*) &out, 8);
    }
    return s;
}


// code == 2 : mean time travel
// code == 1 : mean continue
// code == 0 : mean step instruction
int chkst(int code) {
    // cout<<"in1"<<endl;
    int status;
    if(code != 2) waitpid(child, &status, 0);
    if (WIFSTOPPED(status)) {
        // cout<<"in2"<<endl;
        if(hit_bp_restore_CC && code == 0){ 
            long save_data = ptrace(PTRACE_PEEKDATA, child, Last_Addr, NULL)  ;
            if(ptrace(PTRACE_POKETEXT, child, Last_Addr, (save_data & 0xffffffffffffff00) | (0xcc & 0xff)) != 0) cerr<<"ptrace(PTRACE_POKETEXT) BreakPoint in restore Step"<<endl;
            hit_bp_restore_CC=false;
        }
        if (WSTOPSIG(status) != SIGTRAP) {
            // cerr << "** child process " << child << " stopped by signal (code " << WSTOPSIG(status) << ")" << endl;
            return -1;
        }
        if(ptrace(PTRACE_GETREGS, child, 0, &recent_regs) != 0) cerr<<"ptrace(GETREGS)"<<endl;
        if(code == 0)Current_Addr = recent_regs.rip;
        if(code == 1)Current_Addr = recent_regs.rip-1;
        Last_Addr = Current_Addr;

        // hit the breakpoint or not
        long data = ptrace(PTRACE_PEEKTEXT, child, Current_Addr, NULL);
        for (auto x : bpoints) {
            if (x.addr == Current_Addr && (data & 0x00000000000000ff) == 0xcc) {
                // show breakpoint message
                long save_data = ptrace(PTRACE_PEEKDATA, child, Current_Addr, NULL)  ;
                if(ptrace(PTRACE_POKETEXT, child, Current_Addr, (save_data & ~0xff) | (x.data & 0xff)) != 0) cerr<<"ptrace(PTRACE_POKETEXT) chkst"<<endl;
                cout<<"** hit a breakpoint at 0x" << hex << Current_Addr <<"."<<endl;
                hit_bp_restore_CC = true;
                // ptrace(PTRACE_SETREGS, child, NULL, &recent_regs);
                if(code == 1 ){
                    recent_regs.rip--;
                    if(ptrace(PTRACE_SETREGS, child, 0, &recent_regs) != 0) cerr<<"ptrace(GETREGS)"<<endl;
                }
                
                return 1;
            }
        }
        return 0;
    }
    if (WIFEXITED(status)) {
        
        if (WIFSIGNALED(status))
            cerr << "** child process " << child << " terminiated by signal (code " << WTERMSIG(status) << ")" << endl;
        else
            cerr << "** the target program terminated."<< endl;
        child = 0;
        return -1;
    }
    return 0;
}


void get_code() {
    ifstream f(file_name.c_str(), ios::in | ios::binary | ios::ate);
    streampos size;
    size = f.tellg();
    int codesz = size + 1L;
    code_context = new char [codesz];
    f.seekg(0, ios::beg);
    f.read(code_context, size);
    code_context[size] = 0;
    f.close();
}

void load() {
    elf_init();
    if ((eh = elf_open(file_name.c_str())) == NULL) {
        cerr << "** unable to open '" << file_name << "'." << endl;
        return;
    }
    if (elf_load_all(eh) < 0) {
        cerr << "** unable to load '" << file_name << "'." << endl;
        return;
    }
    for (tab = eh->strtab; tab != NULL; tab = tab->next) {
        if (tab->id == eh->shstrndx) break;
    }
    if (tab == NULL) {
        cerr << "** section header string table not found." << endl;
        return;
    }
    for (int i = 0; i < eh->shnum; i++) {
        if (!strcmp(&tab->data[eh->shdr[i].name], ".text")) {
            
            texts = eh->shdr[i];
            // cout<<i<<endl;
            // cerr << "** program '" << file_name << "' loaded. " << hex
            //     << "entry point 0x" << eh->entrypoint
            //     << ", vaddr 0x" << texts.addr
            //     << ", offset 0x" << texts.offset
            //     << ", size 0x" << texts.size << endl << dec;
            Program_Start_Addr = eh->entrypoint;
            break;
        }
    }
    for (int i = 0; i < eh->phnum; i++) {
        long long end = eh->phdr[i].offset + eh->phdr[i].filesz;
        if (eh->phdr[i].offset <= texts.offset && texts.offset <= end) {
            tphdr = eh->phdr[i];
            break;
        }
    }
}


int load_text_content(){
	FILE *fp;
	if((fp = fopen(file_name.c_str(), "rb")) == NULL) return -1;
    fseek( fp, 0, SEEK_END );
    long int size = ftell(fp);
    // cout<<size<<endl;
	text_content = (char*) malloc( size * sizeof(char));
    memset(text_content,'\0',size);
    fseek( fp, 0, SEEK_SET );
    size_t numread = fread(text_content,sizeof(char) , size , fp);
    // cout<<numread<<endl;
    fclose(fp);
    return 0;
}



void launch(){
    if (child) {
        return;
    }
    child = fork();
    if (child < 0) {
        cerr << "** fork error." << endl;
        return;
    }
    else if (child == 0) {    // child process
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            cerr << "** ptrace error." << endl;
        }
        char **argv = {NULL};
        execvp(file_name.c_str(), argv);
    }
    else {                  // parent process
        int status;
        waitpid(child, &status, 0);
        // if parent is terminated, kill child
        ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);
        // get text base address
        load();
        int check = load_text_content();
        
        // cout<<check<<endl;
        cout << "** program '" << file_name << "' loaded. entry point 0x"<< hex <<Program_Start_Addr << endl;
        // cerr << "** pid " << child << endl;
        Current_Addr = Program_Start_Addr;
    }
}

// string disone(unsigned char *pos, long long &addr) {
//     csh handle;
//     cs_insn *insn;
//     size_t count;
//     string out = "";
//     if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
//         cerr << "** cs open error." << endl;
//         return "";
//     }
//     count = cs_disasm(handle, pos, MAXASM, addr, 0, &insn);
//     if (count > 0) {
//         stringstream ss;
//         ss << hex << setfill(' ') << setw(12) << insn[0].address << ": "
//             << left << setfill(' ') << setw(31) << get_bytes(insn[0].bytes, insn[0].size)
//             << left << setfill(' ') << setw(7) << insn[0].mnemonic
//             << right << insn[0].op_str << endl << dec;
//         addr += insn[0].size;
//         // if (get_bytes(insn[0].bytes, insn[0].size) == "00 00" && strcmp (insn[0].mnemonic , "add") == 0 && strcmp (insn[0].op_str ,"byte ptr [rax], al") == 0 ) return "None!";
//         out = ss.str();
//         cs_free(insn, count);
//     }
//     else {
//         cerr << "** failed to disassemble given code!" << endl;
//     }
//     cs_close(&handle);
//     return out;
// }

// void Disassemble(){
//     if (Current_Addr == -1) {
//         cerr << "** no addr is given." << endl;
//         return;
//     }
//     long long temp_addr = Current_Addr;
//     if (code_context == NULL) get_code();

//     for (int i = 0; i < 5; i++) {
//         if (temp_addr>= texts.size + texts.addr){
//             cout<<"** the address is out of the range of the text section."<<endl;
//             return;
//         } 
//         auto pos = (unsigned char*) code_context + texts.offset + (temp_addr - texts.addr);
//         string out = disone(pos, temp_addr);
//         cerr << out;
//     }

// }

string disone(unsigned char *pos, long long &addr) {
    csh handle;
    cs_insn *insn;
    size_t count;
    string out = "";
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        cerr << "** cs open error." << endl;
        return "";
    }
    count = cs_disasm(handle, pos, MAXASM, addr, 0, &insn);
    if (count > 0) {
        stringstream ss;
        ss << hex << setfill(' ') << setw(12) << insn[0].address << ": "
            << left << setfill(' ') << setw(31) << get_bytes(insn[0].bytes, insn[0].size)
            << left << setfill(' ') << setw(7) << insn[0].mnemonic
            << right << insn[0].op_str << endl << dec;
        addr += insn[0].size;
        // if (get_bytes(insn[0].bytes, insn[0].size) == "00 00" && strcmp (insn[0].mnemonic , "add") == 0 && strcmp (insn[0].op_str ,"byte ptr [rax], al") == 0 ) return "None!";
        out = ss.str();
        cs_free(insn, count);
    }
    else {
        cerr << "** failed to disassemble given code!" << endl;
    }
    cs_close(&handle);
    return out;
}
void Disassemble(){
    if (Current_Addr == -1) {
        cerr << "** no addr is given." << endl;
        return;
    }
    long long temp_addr = Current_Addr;
    if (code_context == NULL) get_code();
    long long addr = texts.offset + (temp_addr - texts.addr);
    for (int i = 0; i < 5; i++) {
        if (temp_addr>= texts.size + texts.addr){
            cout<<"** the address is out of the range of the text section."<<endl;
            return;
        } 
        auto pos = (unsigned char*) text_content + texts.offset + (temp_addr - texts.addr);
        string out = disone(pos, temp_addr);
        cerr << out;
    }

}
void Continue(){
    
    int status;
    // cout<<"!!!!!!!!!!!!"<<endl;
    ptrace(PTRACE_SINGLESTEP, child, NULL, NULL);
    waitpid(child, &status, 0);
    long save_data = ptrace(PTRACE_PEEKDATA, child, Last_Addr, NULL)  ;
    ptrace(PTRACE_POKETEXT, child, Last_Addr, (save_data & 0xffffffffffffff00) | (0xcc & 0xff));
    hit_bp_restore_CC=false;
    
    // restore the breakpoint
    ptrace(PTRACE_CONT, child, NULL, NULL);
    // cheack whether hit the break point or not
    int state = chkst(1);
    if(state !=-1) Disassemble();
}
void BreakPoint(long long addr){
    cout <<"** set a breakpoint at 0x"<<hex<<addr<<endl;
    long save_data = ptrace(PTRACE_PEEKDATA, child, addr, NULL)  ;
    breakpoint temp = breakpoint(addr  , save_data & 0xff, anchor_exist);
    bpoints.push_back(temp);
    // for(auto x : bpoints) cout<<x.addr<<" "<<x.data <<endl;
    if(addr == Current_Addr) return;
    if(ptrace(PTRACE_POKETEXT, child, addr, (save_data & 0xffffffffffffff00) | (0xcc & 0xff)) != 0) cerr<<"ptrace(PTRACE_POKETEXT) BreakPoint"<<endl;
}
void Anchor(){
    if(anchor_exist){
        for(int i = 0 ; i < bpoints.size() ; i++){
            if(Current_Addr >= bpoints[i].addr && bpoints[i].flag == true ){ bpoints[i].flag = false;}
        }
    }
    anchor_exist = true;

    // save the register
    if( ptrace(PTRACE_GETREGS , child , 0 , &anchor_regs) !=0) cerr<<"PTRACE(ANCHOR)"<<endl;
    load_mem();
    cout<<"** dropped an anchor"<<endl;
}
void Timetravel(){
    if( ptrace(PTRACE_SETREGS , child , 0 , &anchor_regs) !=0) cerr<<"PTRACE(TIMETRAVEL)"<<endl;
    if( ptrace(PTRACE_GETREGS , child , 0 , &recent_regs) !=0) cerr<<"PTRACE(ANCHOR)"<<endl;
    Current_Addr = recent_regs.rip;

    // restore the memory content
    for( auto x : mem_content){
        ptrace(PTRACE_POKETEXT, child, x.start_addr, x.data);
        // if((sz = pwrite(fd, x.data.c_str() , x.data.size() , x.start_addr - texts.addr)) < 0)  cerr<<"memory write is failed"<<endl;
    }

    //restore the break point
    for(auto x : bpoints){
        // cout<<x.flag<<" "<<x.addr<<endl;
        if(Current_Addr >= x.addr && x.flag == false ) continue;
        long save_data = ptrace(PTRACE_PEEKDATA, child, x.addr, NULL)  ;
        // cout<<save_data<<endl;
        if(ptrace(PTRACE_POKETEXT, child, x.addr, (save_data & 0xffffffffffffff00) | (0xcc & 0xff)) != 0) cerr<<"ptrace(PTRACE_POKETEXT) BreakPoint"<<endl;
    }

    cout<<"** go back to the anchor point"<<endl;
    chkst(2);
}
void StepInstruction(){
    // reset the bp
    ptrace(PTRACE_SINGLESTEP, child, NULL, NULL);
    int state = chkst(0);
    if(state !=-1) Disassemble();
}

int load_maps(pid_t pid, map<range_t, map_entry_t>& loaded) {
	char fn[128];
	char buf[256];
	FILE *fp;
	snprintf(fn, sizeof(fn), "/proc/%u/maps", pid);
	if((fp = fopen(fn, "rt")) == NULL) return -1;
	while(fgets(buf, sizeof(buf), fp) != NULL) {
		int nargs = 0;
		char *token, *saveptr, *args[8], *ptr = buf;
		map_entry_t m;
		while(nargs < 8 && (token = strtok_r(ptr, " \t\n\r", &saveptr)) != NULL) {
            // cout<<token<<endl;
			args[nargs++] = token;
			ptr = NULL;
		}
		if(nargs < 6) continue;
		if((ptr = strchr(args[0], '-')) != NULL) {
			*ptr = '\0';
			m.range.begin = strtol(args[0], NULL, 16);
			m.range.end = strtol(ptr+1, NULL, 16);
		}
		m.name = basename(args[5]);
		m.perm = 0;
		if(args[1][0] == 'r') m.perm |= 0x04;
		if(args[1][1] == 'w') m.perm |= 0x02;
		if(args[1][2] == 'x') m.perm |= 0x01;
		m.offset = strtol(args[2], NULL, 16);
        loaded[m.range] = m;
	}
	return (int) loaded.size();
}

void load_mem(){
    // save memroy content
    mem_size = load_maps(child, mem);
    if(mem_size <= 0) cerr<<"get memory is error"<<endl;
    for( auto x : mem){
        // cout<<x.first.begin<<"-"<<x.first.end<<endl;
        for (long long addr = x.first.begin ; addr < x.first.end ; addr+=8){
            long data = ptrace(PTRACE_PEEKTEXT, child, addr , NULL);
            memory_content tt = memory_content(addr , data);
            mem_content.push_back(tt);
        }
        if(x.second.name == "[stack]") break;
    }
}

bool operator<(range_t r1, range_t r2) {
	if(r1.begin < r2.begin && r1.end < r2.end) return true;
	return false;
}