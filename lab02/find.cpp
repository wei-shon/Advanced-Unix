#include <iostream>
#include <dirent.h>
// #include <sys/types.h>
#include <vector>
#include <string>
#include <fstream>

using namespace std;
int main(int argc , char* argv[]) {
    char* path = argv[1];
    string answer = argv[2];
    vector<string> file;
    vector<string> dir_name;
    dir_name.push_back(string(path));
    while(dir_name.size()!=0){
        DIR *dr;
        struct dirent *en;
        // cout<<"i open dir:"<<dir_name.front()<<endl;
        dr = opendir(dir_name.front().c_str()); //open all directory
        if (dr) {
            while ((en = readdir(dr)) != NULL) {
                // cout<<en->d_name<<endl;
                string a = string(en->d_name);
                if(a=="."||a=="..") continue;
                // if (!f->d_name || f->d_name[0] == '.') continue;
                if (en->d_type == DT_DIR) 
                    dir_name.push_back(dir_name.front()+"/"+a);

                if (en->d_type == DT_REG)
                    file.push_back(dir_name.front()+"/"+a);

            }
            closedir(dr); //close all directory
        }
        for(auto it:file){
            // cerr<<it<<endl;
            ifstream file_text (it);
            string eachline;
            if (file_text.is_open())       //is_open open the text file.
            {
                while ( getline (file_text,eachline) )    
                {
                    cerr<<eachline<<endl;
                    if (eachline.find(answer) != string::npos) cout<<it<<endl;
                }
            }
        }
        file.clear();
        dir_name.erase(dir_name.begin());

    }
    


    // DIR *dir;
    // struct dirent *ent;
    // if ((dir = opendir (path)) != NULL) {
    // /* print all the files and directories within directory */
    // while ((ent = readdir (dir)) != NULL) {
    //     // if(ent->d_name == "." || )
    //     cerr<<ent->d_name<<endl;
    // }
    // closedir (dir);
    // } else {
    // /* could not open directory */
    // perror ("");
    // return EXIT_FAILURE;
    // }
    return(0);
}