#include "fle.hpp"
#include <cassert>
#include <iostream>
#include <map>
#include <stdexcept>
#include <vector>
#include <stdio.h>
#include <unordered_set>
#include <queue>
using namespace std;

FLEObject FLE_ld(const std::vector<FLEObject>& objects, const LinkerOptions& options)
{

    // TODO: 实现链接器
    FLEObject result;
    vector<FLEObject> curr_objs;
    vector<FLEObject> curr_ars;
    unordered_set <string> obj_names;
    queue <FLEObject> to_process;
    unordered_map <string,string> so_symbol_section;
    unordered_map <string,int> so_symbol_offset;

    result.name = options.outputFile;  // 程序名在options里
    if(options.shared == true)
    {
        result.type = ".so"; // 输出为共享库文件
    }
    else 
    { 
        result.type = ".exe"; // 输出为可执行文件
    }
    uint64_t base_vaddr = 0x400000; // 基础地址
    size_t page_size = 0x1000; // x86_64 页面大小对齐

    // 区分静态库与目标文件与共享库
    for(size_t obj_idx = 0; obj_idx < objects.size(); ++obj_idx)
    {
        const auto& obj = objects[obj_idx];
        if(obj.type == ".ar") curr_ars.push_back(obj);
        else if(obj.type == ".obj") 
        {
            curr_objs.push_back(obj);
            obj_names.insert(obj.name);
            to_process.push(obj);
        }
        else  // 共享库：直接记录为依赖（无需链接，运行时加载）
        {
            
            result.needed.push_back(obj.name);            
            for(const auto& sym : obj.symbols)
            {
                if(sym.type == SymbolType::UNDEFINED) continue;     // 未定义符号说明这个符号的定义不来自这个文件
                so_symbol_section[sym.name] = sym.section;
                so_symbol_offset[sym.name] = sym.offset;
            }
        }
    }

    // 按需链接
    while(!to_process.empty())
    {       
        const auto& obj = to_process.front();
        to_process.pop();
        unordered_set <string> Undef_syms;
        unordered_set <string> Def_syms;
        // 遍历符号表，看有没有符号来自没被加入的目标文件的
        // （准确来说是还没被加到obj_names的）
        // 有的话就去静态库表里找
        for (const auto& sym : obj.symbols) 
        {
            // 跳过已定义符号
            if (sym.type != SymbolType::UNDEFINED) continue;
            else 
            {
                Undef_syms.insert(sym.name);
            }
        }
        for (const auto& sym : obj.symbols) 
        {
            if (sym.type == SymbolType::UNDEFINED) continue; // 跳过未定义符号
            Def_syms.insert(sym.name); // 收集当前obj的已定义符号
        }
        // 遍历静态库
        for(const auto& ar : curr_ars)
        {
            for(const auto& member : ar.members)
            {
                if(obj_names.count(member.name)) continue;
                for(const auto& sym : member.symbols)
                {
                    // 找到了有符号依赖而且从来没被更新过的目标文件
                    if(Undef_syms.count(sym.name) && (!Def_syms.count(sym.name)))
                    {
                        curr_objs.push_back(member);
                        obj_names.insert(member.name);
                        Def_syms.insert(sym.name);
                        to_process.push(member);
                    }
                }
            }
        }
    }
   
    map<string, FLESection> merged_sec; // 合并后的节
    map<string, vector<uint8_t>> merged_sec_data;
    int64_t current_vaddr = base_vaddr; // 当前合并节更新到的地址
    vector<string> section_order = {".text",".plt",".rodata",".got",".data",".bss"};

    struct SecInfo 
    {
        int64_t addr;
        size_t size;
    };

    map<string, SecInfo> global_sections; // 全局的大合并节的初始位置和大小
    map<pair<size_t,string>, size_t> pre_sec_addr; // 原来的小节在原文件的起始地址

    // 初始化global_sections
    for (const auto& head: section_order)
    {
        global_sections[head] = SecInfo{0, 0};
    }

    // 第一次遍历：合并节 + 分配内存地址
    // 先合并节
    for (size_t obj_idx = 0; obj_idx < curr_objs.size(); ++obj_idx)
    {
        const auto& obj = curr_objs[obj_idx];
        // 先遍历节头，记录各小节的大小
        for (const auto& shdr : obj.shdrs) 
        {
            // bss 没啥用（.bss 节 data 为空，不用合并）
            if (shdr.type == 8) 
            {
                pre_sec_addr[{obj_idx, shdr.name}] = global_sections[".bss"].size;
                global_sections[".bss"].size += shdr.size;
                continue;
            }

            std::string sec_name = shdr.name;
            const auto& sec = obj.sections.at(sec_name);
            bool matched = false;
            for (const auto& head: section_order)
            {
                // 找到对应的节
                if (sec_name.starts_with(head))
                {
                    // 合并内存
                    merged_sec[head].data.insert
                    (
                        merged_sec[head].data.end(),
                        sec.data.begin(),
                        sec.data.end()
                    );
                    // 重定位不用补0了，原本的输入已经补好了。
                    // 存下当前小节在合并大节后的初始位置
                    pre_sec_addr[{obj_idx, sec_name}] = global_sections[head].size;
                    // 相应的，更新到下一个小节的初始位置
                    global_sections[head].size += shdr.size;
                    matched = true;
                    // 就不能合并重定位标，不然program还以为那个地方是重定位的
                    merged_sec[head].has_symbols |= sec.has_symbols;
                    break;
                }
            }
            if (!matched) 
            {
                throw std::runtime_error("Unknown section: " + sec_name);
            }
        }
    }

    // 第二次遍历：构建全局符号表 + 处理符号冲突
    map<string, Symbol> global_symbols; // 全局符号表
    unordered_set<string> external_symbols; // 所有外部符号（需动态解析）

    for (size_t obj_idx = 0; obj_idx < curr_objs.size(); ++obj_idx) 
    {
        const auto& obj = curr_objs[obj_idx];
        for (const auto& sym : obj.symbols) 
        {
            // 将未定义符号名称加入到外部符号集合，然后跳过；
            // 未定义符号的section,offset和size都为0
            // 不过这里的未定义符号还不能保证一定是外部符号
            // 但是他在.so库里面就是正常的符号
            // 共享库才考虑外部符号
            if (sym.type == SymbolType::UNDEFINED) 
            {
                external_symbols.insert(sym.name);
                continue;
            }
            else if(sym.type == SymbolType::WEAK && sym.section != ".text") // 弱变量符号
            {
                external_symbols.insert(sym.name);
            }
            Symbol global_sym = sym;

            // 局部符号名称要加个文件名前缀
            if (sym.type == SymbolType::LOCAL) global_sym.name = obj.name + "::" + sym.name;
            
            // 计算符号最终地址 = 节起始地址 + 符号在节内偏移
            for (const auto& head: section_order)
            {
                if (sym.section.starts_with(head))
                {
                    // 原小节在合并大节中的起始地址
                    size_t sec_off = pre_sec_addr.at({obj_idx, sym.section});
                    // 全局变量改个合并节偏移量再把合并节改成一般名称就行
                    global_sym.offset = sec_off + sym.offset;
                    global_sym.section = head;
                    break;
                }
            }

            // 处理符号冲突：强符号覆盖弱符号，局部符号不冲突
            if (global_symbols.count(global_sym.name)) 
            {
                const auto& existing_sym = global_symbols[global_sym.name];
                // 冲突规则：GLOBAL > WEAK > LOCAL
                bool need_replace = false;
                if (global_sym.type == SymbolType::GLOBAL && existing_sym.type != SymbolType::GLOBAL) 
                {
                    // 当前的为全局符号而表里的不是，那么就要替换
                    need_replace = true;
                } 
                else if (global_sym.type == SymbolType::WEAK && existing_sym.type == SymbolType::LOCAL) 
                {
                    // 当前为弱符号而表里是局部符号，那么也要替换
                    need_replace = true;
                } 
                else if (global_sym.type == existing_sym.type && global_sym.type == SymbolType::GLOBAL) 
                {
                    // 同时存在两个相同的全局变量，抛出异常
                    throw runtime_error("Multiple definition of strong symbol: " + sym.name);
                }

                // 当前的符号无法替换表内的符号，那么就跳过。
                if (!need_replace) continue;
            }

            global_symbols[global_sym.name] = global_sym;
        }
    }

    // 把 external_symbols 里面实际上不是外部符号的去掉
    for (size_t obj_idx = 0; obj_idx < curr_objs.size(); ++obj_idx) 
    {
        auto& obj = curr_objs[obj_idx];
        for(const auto& shdr : obj.shdrs)
        {
            if(shdr.type == 8) continue;
            string sec_name = shdr.name;
            auto& sec = obj.sections.at(sec_name);
            for (const auto& reloc : sec.relocs)
            {
                if(global_symbols.count(reloc.symbol) || (!so_symbol_section.count(reloc.symbol)))
                {
                    // 把未定义但不是外部符号的去掉了
                    if(options.shared == false) external_symbols.erase(reloc.symbol);
                }
            }
        }
    }

    unordered_map<string,int> got_sym;
    unordered_map<string,int> plt_sym;
    int got_idx = 0,plt_idx = 0;

    // 先构建符号与GOT表和PLT表之间的映射关系
    for(const auto& sym_name : external_symbols)
    {
        if(so_symbol_section[sym_name] == ".text")
        {
            // 外部函数
            got_sym[sym_name] = got_idx;
            plt_sym[sym_name] = plt_idx;  
            got_idx++;
            plt_idx++;
        }
        else
        {
            // 外部数据
            got_sym[sym_name] = got_idx;
            got_idx++;
        }
    }

    // 然后由于要算地址，这两个表占内存，先填充0吧
    merged_sec[".got"].data.resize(got_sym.size() * 8,0);
    merged_sec[".plt"].data.resize(plt_sym.size() * 6,0);
    global_sections[".got"].size = merged_sec[".got"].data.size();
    global_sections[".plt"].size = merged_sec[".plt"].data.size();

    // 分配节的地址
    for (const auto& sec_name : section_order) 
    {
        // 读取节
        auto& sec = merged_sec[sec_name];
        // 记录当前节的初始位置
        global_sections[sec_name].addr = current_vaddr;

        // 更新节大小（.bss 节从输入节累计大小）
        if (sec_name.starts_with(".bss")) 
        {
            // resize（a,b） 表示新增a个全部初始化为b的元素
            sec.data.resize(global_sections[".bss"].size, 0); // 填充0占位
        }

        // 推进当前地址（按节实际大小分配）
        // 也就是合并大节的初始位置
        // 而且地址要满足为 页大小 的整数倍
        current_vaddr += sec.data.size();
        current_vaddr = (current_vaddr + page_size - 1) / page_size * page_size;
    }

    // 得到 .got 的地址后进行重定位
    // 先构建符号与GOT表和PLT表之间的映射关系
    for(const auto& sym_name : external_symbols)
    {
        if(so_symbol_section[sym_name] == ".text")
        {
            // 外部函数
            // 创建重定位项
            Relocation reloc;
            reloc.type = RelocationType::R_X86_64_64;
            reloc.addend = 0;
            reloc.symbol = sym_name;
            reloc.offset = global_sections[".got"].addr;
            result.dyn_relocs.push_back(reloc);
        }
        else
        {
            // 外部数据
            // 创建重定位项
            Relocation reloc;
            reloc.type = RelocationType::R_X86_64_64;
            reloc.addend = 0;
            reloc.symbol = sym_name;
            reloc.offset = global_sections[".got"].addr;
            result.dyn_relocs.push_back(reloc);
        }
        
    }    

    // 生成PLT stub 然后填入plt表中
    for(auto& [sym_name,plt_idx] : plt_sym)
    {
        int64_t got_addr = global_sections[".got"].addr + got_sym[sym_name] * 8;
        int64_t plt_addr = global_sections[".plt"].addr + plt_idx * 6;
        int64_t got_offset = got_addr - (plt_addr + 6) ;
        vector<uint8_t> stub = generate_plt_stub(got_offset);
        // 更新plt中的数据
        for(int i = 0;i < 6;i++)
        {
            merged_sec[".plt"].data[plt_idx * 6 + i]  = stub[i];   

        }
    }

    // 第三次遍历：处理重定位
    for (size_t obj_idx = 0; obj_idx < curr_objs.size(); ++obj_idx) 
    {
        auto& obj = curr_objs[obj_idx];
        for(const auto& shdr : obj.shdrs)
        {
            if(shdr.type == 8) continue;
            string sec_name = shdr.name;
            auto& sec = obj.sections.at(sec_name);
            // 合并节内小节偏移量
            int64_t curr_off = pre_sec_addr.at({obj_idx, sec_name});
            int64_t curr_addr;
            string now_sec;
            // 得到当前内存地址（但不含偏移）
            for(auto head : section_order)
            {
                if(sec_name.starts_with(head))
                {
                    now_sec = head;
                    curr_addr = global_sections[head].addr + curr_off;
                    break;
                }
            }
            for (const auto& reloc : sec.relocs)
            {
                // 先试一试局部符号
                string sym_name = obj.name + "::" + reloc.symbol;

                // 全局符号表里面没这个符号名的局部符号形式，说明他不是局部变量
                if(!global_symbols.count(sym_name))
                {
                    sym_name = reloc.symbol;
                }

                // 共享库下对于外部符号的重定位
                if(external_symbols.count(sym_name))
                {
                    int64_t reloc_value;
                    if(reloc.type == RelocationType::R_X86_64_PC32) // 外部函数
                    {
                        int64_t plt_addr = global_sections[".plt"].addr + plt_sym[sym_name] * 6;
                        int64_t reloc_addr = curr_addr + reloc.offset;
                        reloc_value = static_cast<int64_t>(plt_addr + reloc.addend - reloc_addr);
                        cout << sym_name << " " << reloc_value << " " << reloc_addr << " "  << plt_addr << " " << reloc.addend << endl;
                    }
                    else // 外部数据
                    {
                        int64_t got_addr = global_sections[".got"].addr + got_sym[sym_name] * 8;
                        int64_t reloc_addr = curr_addr + reloc.offset;
                        reloc_value = static_cast<int64_t>(got_addr + reloc.addend - reloc_addr);
                    }

                    // 重定位32位相对地址
                    merged_sec[now_sec].data[curr_off + reloc.offset]     = reloc_value & 0xFF;         // 最低字节
                    merged_sec[now_sec].data[curr_off + reloc.offset + 1] = (reloc_value >> 8) & 0xFF;
                    merged_sec[now_sec].data[curr_off + reloc.offset + 2] = (reloc_value >> 16) & 0xFF;
                    merged_sec[now_sec].data[curr_off + reloc.offset + 3] = (reloc_value >> 24) & 0xFF; // 最高字节  
                }
                else // 静态链接重定位
                {
                    // 静态链接下重定位的符号不存在，报错离开
                    if(!global_symbols.count(sym_name))
                    {
                        if(options.shared)
                        {
                            continue;
                        }
                        else
                        {
                            throw runtime_error("Relocation points to an undefined symbol: " + sym_name);
                        }
                    }
                    
                    // 要找当前符号的地址，而不是要填在的内存的地方
                    int64_t S = global_symbols.at(sym_name).offset + global_sections[global_symbols.at(sym_name).section].addr;
                    // 小偏移量
                    int64_t A = reloc.addend;
                    // 重定位的内存地址
                    int64_t P = curr_addr + reloc.offset;
                    // 按小端序写入节数据
                    if(reloc.type == RelocationType::R_X86_64_64)
                    {
                        uint64_t reloc_value = static_cast<uint64_t>(S + A);
                        // 64位绝对地址
                        merged_sec[now_sec].data[curr_off + reloc.offset]     = (reloc_value) & 0xFF;         // 最低字节
                        merged_sec[now_sec].data[curr_off + reloc.offset + 1] = (reloc_value >> 8) & 0xFF;
                        merged_sec[now_sec].data[curr_off + reloc.offset + 2] = (reloc_value >> 16) & 0xFF;
                        merged_sec[now_sec].data[curr_off + reloc.offset + 3] = (reloc_value >> 24) & 0xFF;
                        merged_sec[now_sec].data[curr_off + reloc.offset + 4] = (reloc_value >> 32) & 0xFF;  
                        merged_sec[now_sec].data[curr_off + reloc.offset + 5] = (reloc_value >> 40) & 0xFF;
                        merged_sec[now_sec].data[curr_off + reloc.offset + 6] = (reloc_value >> 48) & 0xFF;
                        merged_sec[now_sec].data[curr_off + reloc.offset + 7] = (reloc_value >> 56) & 0xFF; // 最高字节
                    }
                    else if(reloc.type == RelocationType::R_X86_64_32 || reloc.type == RelocationType::R_X86_64_32S)
                    {
                        uint32_t reloc_value = static_cast<uint32_t>(S + A);
                        // 32位绝对地址
                        merged_sec[now_sec].data[curr_off + reloc.offset]     = reloc_value & 0xFF;         // 最低字节
                        merged_sec[now_sec].data[curr_off + reloc.offset + 1] = (reloc_value >> 8) & 0xFF;
                        merged_sec[now_sec].data[curr_off + reloc.offset + 2] = (reloc_value >> 16) & 0xFF;
                        merged_sec[now_sec].data[curr_off + reloc.offset + 3] = (reloc_value >> 24) & 0xFF; // 最高字节
                    }
                    else //  (reloc.type == RelocationType::R_X86_64_PC32)
                    {
                        int32_t reloc_value = static_cast<int64_t>(S + A - P);
                        // 32位相对地址
                        merged_sec[now_sec].data[curr_off + reloc.offset]     = reloc_value & 0xFF;         // 最低字节
                        merged_sec[now_sec].data[curr_off + reloc.offset + 1] = (reloc_value >> 8) & 0xFF;
                        merged_sec[now_sec].data[curr_off + reloc.offset + 2] = (reloc_value >> 16) & 0xFF;
                        merged_sec[now_sec].data[curr_off + reloc.offset + 3] = (reloc_value >> 24) & 0xFF; // 最高字节
                    }   
                }
            }
        }
    }

// 生成程序头(phdrs)
for (const auto& head: section_order)
{
    if(merged_sec[head].data.size() == 0) continue;
    // 保存合并后的节
    result.sections[head] = merged_sec[head];

    ProgramHeader phdr;
    phdr.name = head;
    phdr.vaddr = global_sections[head].addr;
    phdr.size = global_sections[head].size;
    if (head == ".text")  phdr.flags = PHF::R | PHF::X;
    else if (head == ".rodata")  phdr.flags = static_cast<uint32_t>(PHF::R);
    else if (head == ".data")  phdr.flags = PHF::R | PHF::W;
    else if (head == ".bss")  phdr.flags = PHF::R | PHF::W;
    else if (head == ".got") phdr.flags = PHF::R | PHF::W;
    else if (head == ".plt") phdr.flags = PHF::R | PHF::X;
    result.phdrs.push_back(phdr);
}

// 构建输出节头（shdrs）
for (const auto& [sec_name, sec] : merged_sec) 
{
    SectionHeader shdr;
    shdr.name = sec_name;
    // 只有bss不用文件空间设为8（SHT_NOBITS），其他的设为1（SHT_PROGBITS）
    shdr.type = (sec_name.starts_with(".bss")) ? 8 : 1;
    // 地址读一下
    shdr.addr = global_sections[sec_name].addr;
    // 节在文件中的位置，基础实现简化为0
    shdr.offset = 0; 
    // 大小等于data的size，一个元素是一个字节
    shdr.size = sec.data.size();
    if(sec.data.size() == 0) continue;
    // 节头标志
    uint32_t flags = 0;
    if (sec_name == ".text" || sec_name == ".plt") {
        // .text/.plt是代码段：需要分配内存 + 可执行
        flags = SHF::ALLOC | SHF::EXEC;
    } 
    else if (sec_name == ".got" || sec_name == ".data" || sec_name == ".bss") {
        // .got/.data/.bss是数据段：需要分配内存 + 可写
        flags = SHF::ALLOC | SHF::WRITE;
    } 
    else if (sec_name == ".rodata") {
        // .rodata是只读数据段：只需要分配内存
        flags = static_cast<uint32_t>(SHF::ALLOC);
    }
    shdr.flags = flags;

    // 加到输出节头里面
    result.shdrs.push_back(shdr);
}

if(options.shared == false)
{
    // 可执行文件检查入口点是否存在，避免无效访问
    // 找到程序入口符号
    auto entry_it = global_symbols.find(options.entryPoint);
    if (entry_it == global_symbols.end()) 
    {
        throw runtime_error("Entry point '" + options.entryPoint + "' not found in global symbols");
    }
    else result.entry = entry_it->second.offset + global_sections[entry_it->second.section].addr; // _start 的最终地址
    // cout << global_sections[entry_it->second.section].addr << " " << entry_it->second.offset << " " << result.entry << endl;
}
else
{
    result.entry = 0; // 共享库入口为0
}

// 填充最终结果的符号表（关键：解决符号表为空的问题）
for (const auto& [sym_name, sym] : global_symbols) 
{
    // 局部符号就不导出来了
    if (sym.type == SymbolType::LOCAL) continue;
    result.symbols.push_back(sym);
}

return result;

}
