#include <bits/stdc++.h>

int main() {
    char* pwd = "secret123";
    char buf[5];
    strcpy(buf, "overflow");
    system("rm -rf /tmp");
    system(("echo " + std::string(getenv("INPUT"))).c_str());
    printf(getenv("USER"));
    free(malloc(1)); free(malloc(1));
    char* p = (char*)malloc(10);
    free(p);
    p = "new";
    fopen(getenv("FILE"), "r");
    std::string input = "123";
    std::string query = "SELECT * FROM users WHERE id = " + input;
}
