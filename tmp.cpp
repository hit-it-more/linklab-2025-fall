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

    result.name = options.outputFile;  // 程序名在options里
    if(options.shared == true)
    {
        result.type = ".so"; // 输出为可执行文件
    }
    else 
    { 
        result.type = ".exe"; // 输出为可执行文件
    }
    uint64_t base_vaddr = 0x400000; // 基础地址（改为uint64_t，与地址类型一致）
    size_t page_size = 0x1000; // x86_64 页面大小对齐

    // 区分静态库与目标文件
    for(size_t obj_idx = 0; obj_idx < objects.size(); ++obj_idx)
    {
        const auto& obj = objects[obj_idx];
        if(obj.type == ".ar") curr_ars.push_back(obj);
        else if(obj.type == ".obj" || obj.type == ".so") 
        {
            curr_objs.push_back(obj);
            obj_names.insert(obj.name);
            to_process.push(obj);
            // 共享库：直接记录为依赖（无需链接，运行时加载）
            if (obj.type == ".so") 
            {
                result.needed.push_back(obj.name);
            }
        }
    }

    // 静态库（如.a文件）：在程序的编译链接阶段，
    // 会被 “合并” 到最终的可执行文件里（把静态库的代码 / 数据直接嵌入可执行文件），
    // 最终可执行文件是独立的。
    // 共享库（如.so文件）：在程序的编译链接阶段，
    // 只会记录 “依赖该共享库” 的信息（不会把共享库的内容合并进去）；等程序运行时
    // ，动态链接器才会加载共享库到进程内存中，让程序和共享库 “动态关联”，但二者始终是独立的文件 / 内存区域。

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
   
    // 第三步：节配置与初始化（.plt紧跟.text，.got在.data后）
    const vector<string> section_order = {".text", ".plt", ".rodata", ".data", ".got", ".bss"};
    map<string, FLESection> merged_sec; // 合并后的节
    map<string, vector<uint8_t>> merged_sec_data;
    uint64_t current_vaddr = base_vaddr; // 添加uint64_t类型声明


    struct SecInfo 
    {
        uint64_t addr;
        size_t size;
    };

    map<string, SecInfo> global_sections; // 全局的大合并节的初始位置和大小
    map<pair<size_t,string>, size_t> pre_sec_addr; // 原来的小节在原文件的起始地址

    // 初始化global_sections
    for (const auto& head: section_order)
    {
        global_sections[head] = SecInfo{0, 0};
        merged_sec[head] = FLESection{
            .name = head,
            .data = {},
            .relocs = {},
            .has_symbols = false
        };
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
                    // merged_sec[head].relocs.insert(merged_sec[head].relocs.end(), sec.relocs.begin(), sec.relocs.end());
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

    // 第二次遍历：构建全局符号表 + 处理符号冲突
    map<string, Symbol> global_symbols;          // 全局符号表
    unordered_set<string> external_symbols;      // 所有外部符号（需动态解析）
    unordered_set<string> external_func_symbols; // 外部函数符号（需生成PLT stub）
    map<string, size_t> got_symbol_index;        // 符号 → GOT槽位索引
    map<string, size_t> plt_symbol_index;        // 函数 → PLT stub索引
    map<string, uint64_t> got_entry_addrs;       // 符号 → GOT槽位地址

    for (size_t obj_idx = 0; obj_idx < curr_objs.size(); ++obj_idx) 
    {
        const auto& obj = curr_objs[obj_idx];
        for (const auto& sym : obj.symbols) 
        {
            // 将未定义符号加入到外部符号集合，然后跳过；
            if (sym.type == SymbolType::UNDEFINED) 
            {
                external_symbols.insert(sym.name);
                continue;
            }

            Symbol global_sym = sym;

            // 局部符号名称要加个文件名前缀
            if (sym.type == SymbolType::LOCAL) global_sym.name = obj.name + "::" + sym.name;
            
            // 计算符号最终地址 = 节起始地址 + 符号在节内偏移
            for (const auto& head: section_order)
            {
                if (sym.section.starts_with(head))
                {
                    // 原节在合并大节中的起始地址
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

    // 为外部符号分配GOT槽位（每个符号8字节）
    auto& got_sec = merged_sec[".got"];
    size_t got_slot_count = external_symbols.size();
    size_t got_total_size = got_slot_count * 8; // 64位地址→8字节/槽位
    got_sec.data.resize(got_total_size, 0); // 初始化填充0，运行时由加载器覆盖
    global_sections[".got"].size = got_total_size;

    // 记录每个外部符号的GOT槽位索引和地址
    size_t current_got_idx = 0;
    for (const auto& sym_name : external_symbols)
    {
        got_symbol_index[sym_name] = current_got_idx;
        uint64_t got_addr = global_sections[".got"].addr + (current_got_idx * 8);
        got_entry_addrs[sym_name] = got_addr;
        current_got_idx++;
    }

    // 生成PLT stub（Bonus2核心：仅外部函数，每个6字节）
    auto& plt_sec = merged_sec[".plt"];
    uint64_t current_plt_addr = global_sections[".plt"].addr; // PLT节基址
    size_t current_plt_idx = 0;

    for (const auto& sym_name : external_symbols)
    {
        // 判断是否为函数符号
        bool is_function = false;
        if (global_symbols.count(sym_name))
        {
            const auto& sym = global_symbols[sym_name];
            // 函数会被放到text节，数据放到data节
            is_function = (sym.section == ".text");
        }

        // 不是外部函数，终止吧
        if (!is_function) continue;

        // 记录PLT stub索引
        plt_symbol_index[sym_name] = current_plt_idx;

        // 计算PLT stub的offset：offset = GOT地址 - (stub地址 + 6)
        uint64_t got_addr = got_entry_addrs[sym_name];
        int32_t offset = static_cast<int32_t>(got_addr - (current_plt_addr + 6));

        // 生成6字节PLT stub（使用框架提供的helper函数）
        vector<uint8_t> stub = generate_plt_stub(offset);
        
        plt_sec.data.insert(plt_sec.data.end(), stub.begin(), stub.end());

        // 更新PLT地址和索引（每个stub占6字节）
        current_plt_addr += 6;
        current_plt_idx++;
    }
    global_sections[".plt"].size = plt_sec.data.size();

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
            uint64_t curr_off = pre_sec_addr.at({obj_idx, sec_name});
            uint64_t curr_addr;
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

                if (external_symbols.count(sym_name)) 
                {
                    // 外部符号重定位
                    // 重定位类型：R_X86_64_PC32 + 外部函数 → 指向PLT stub
                    if (reloc.type == RelocationType::R_X86_64_PC32 && external_func_symbols.count(sym_name)) 
                    {
                        // 校验PLT索引和内存空间
                        if (!plt_symbol_index.count(sym_name)) continue;
                        uint64_t final_offset = curr_off + reloc.offset;
                        auto& merged_data = merged_sec[now_sec].data;
                        if (final_offset + 3 >= merged_data.size()) continue;

                        // 计算PLT stub的相对偏移（公式：PLT地址 - 当前RIP地址）
                        uint64_t plt_addr = global_sections[".plt"].addr + (plt_symbol_index[sym_name] * 6);
                        int64_t P = curr_addr + reloc.offset;
                        int32_t reloc_value = static_cast<int32_t>(plt_addr + reloc.addend - P);

                        // 小端序写入4字节偏移
                        merged_data[final_offset]     = reloc_value & 0xFF;
                        merged_data[final_offset + 1] = (reloc_value >> 8) & 0xFF;
                        merged_data[final_offset + 2] = (reloc_value >> 16) & 0xFF;
                        merged_data[final_offset + 3] = (reloc_value >> 24) & 0xFF;
                    }

                    // 所有外部符号均记录到动态重定位表
                    continue;
                }

                if (!global_symbols.count(sym_name)) 
                {
                    if (!options.shared) {
                        throw runtime_error("Undefined internal symbol: " + sym_name);
                    }
                    continue;
                }
                
                // 内部符号重定位
                // 要找当前符号的地址，而不是要填在的内存的地方
                int64_t S = global_symbols.at(sym_name).offset + global_sections[global_symbols.at(sym_name).section].addr;
                // 小偏移量
                int64_t A = reloc.addend;
                // 重定位的内存地址
                int64_t P = curr_addr + reloc.offset;
                // 按小端序写入节数据
                if (reloc.type == RelocationType::R_X86_64_32 || reloc.type == RelocationType::R_X86_64_32S)
                {
                    uint32_t reloc_value = static_cast<uint32_t>(S + A);
                    // 32位绝对地址
                    merged_sec[now_sec].data[curr_off + reloc.offset]     = reloc_value & 0xFF;         // 最低字节
                    merged_sec[now_sec].data[curr_off + reloc.offset + 1] = (reloc_value >> 8) & 0xFF;
                    merged_sec[now_sec].data[curr_off + reloc.offset + 2] = (reloc_value >> 16) & 0xFF;
                    merged_sec[now_sec].data[curr_off + reloc.offset + 3] = (reloc_value >> 24) & 0xFF; // 最高字节
                }
                else if(reloc.type == RelocationType::R_X86_64_PC32)
                {
                    int32_t reloc_value = static_cast<int64_t>(S + A - P);
                    // 32位相对地址
                    merged_sec[now_sec].data[curr_off + reloc.offset]     = reloc_value & 0xFF;         // 最低字节
                    merged_sec[now_sec].data[curr_off + reloc.offset + 1] = (reloc_value >> 8) & 0xFF;
                    merged_sec[now_sec].data[curr_off + reloc.offset + 2] = (reloc_value >> 16) & 0xFF;
                    merged_sec[now_sec].data[curr_off + reloc.offset + 3] = (reloc_value >> 24) & 0xFF; // 最高字节
                }
                else if(reloc.type == RelocationType::R_X86_64_64)
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
            }
        }
    }

    // 生成动态重定位表（告知加载器填充GOT槽位）
    result.dyn_relocs.clear();
    for (const auto& [sym_name, got_idx] : got_symbol_index) {
        Relocation dyn_reloc;
        dyn_reloc.type = RelocationType::R_X86_64_64; // 64位地址填充
        dyn_reloc.offset = got_idx * 8;               // GOT槽位内偏移
        dyn_reloc.symbol = sym_name;
        dyn_reloc.addend = 0;
        result.dyn_relocs.push_back(dyn_reloc);
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
        // 加到输出节头里面
        result.shdrs.push_back(shdr);
    }

    // 生成程序头
    for (const auto& head: section_order)
    {
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
        result.phdrs.push_back(phdr);
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
    }
    
    // 填充输出符号表（仅导出全局/弱符号）
    result.symbols.clear();
    for (const auto& [sym_name, sym] : global_symbols) {
        if (sym.type == SymbolType::GLOBAL || sym.type == SymbolType::WEAK) {
            result.symbols.push_back(sym);
        }
    }

    return result;
}