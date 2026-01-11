#include "fle.hpp"
#include <iomanip>
#include <iostream>
#include <string.h>
#include <map>
using namespace std;

enum class SectionType {
    LOCAL, // Local symbol (🏷️)
    WEAK, // Weak global symbol (📎)
    GLOBAL, // Strong global symbol (📤)
    UNDEFINED // Undefined symbol
};

void FLE_nm(const FLEObject& obj)
{
    // TODO: 实现符号表显示工具
    vector<Symbol> symbols = obj.symbols;

    // 遍历符号表
    for(const auto& symbol : symbols) 
    {
        if(symbol.section == "") continue;
        size_t addr = symbol.offset;
        string section = symbol.section;
        string type;
        switch(symbol.type)
        {
            case SymbolType::LOCAL:      
                {
                    if (section == ".text") { type = 't';} 
                    else if (section == ".data") { type = 'd';} 
                    else if (section == ".bss") { type = 'b';} 
                    else if (section == ".rodata") { type = 'r';}
                    break;
                }
            case SymbolType::WEAK:       
                {
                    if (section == ".text") { type = 'W';} 
                    else if (section == ".data") { type = 'V';} 
                    else if (section == ".bss") { type = 'V';} 
                    else if (section == ".rodata") { type = 'V';}
                    break;
                }
            case SymbolType::GLOBAL:     
                {
                    if (section == ".text") { type = 'T';} 
                    else if (section == ".data") { type = 'D';} 
                    else if (section == ".bss") { type = 'B';} 
                    else if (section == ".rodata") { type = 'R';}
                    break;
                }
            case SymbolType::UNDEFINED:  
                {   
                    type = "UNDEF";break; 
                }
        }
        string name = symbol.name;
        printf("%016lx ", addr);  // C 风格,输出16位的十六进制数,左侧补0
        cout << type << " ";
        cout << name << endl;
    }
}