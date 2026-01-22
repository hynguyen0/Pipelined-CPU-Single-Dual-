#include <iostream>
#include <iomanip>
#include <string>
#include <bitset>
#include <cstdint>
#include <cstring>
#include <random>
#include <deque>
#include <vector>
#include <optional>
#include <fstream>
#include <sstream>
#include <map>
#include <cctype>
#include <cstdio>

using namespace std;

//RAM & CONSTANTS
constexpr uint32_t RAM_SIZE       = 0x1400;  // 0x0000–0x13FF

constexpr uint32_t STACK_START    = 0x0200;
constexpr uint32_t STACK_END      = 0x02FF;

// Hard-coded array mapping (like CPU0.txt expects)
constexpr uint32_t ARRAY_A_START  = 0x0400;  // 1024
constexpr uint32_t ARRAY_A_END    = 0x07FF;  // 2047

constexpr uint32_t ARRAY_B_START  = 0x0800;  // 2048
constexpr uint32_t ARRAY_B_END    = 0x0BFF;  // 3071

constexpr uint32_t ARRAY_C_START  = 0x0C00;  // 3072
constexpr uint32_t ARRAY_C_END    = 0x0FFF;  // 4095

constexpr uint32_t ARRAY_LEN      = 0x0400;  // 1 KB per array
constexpr uint32_t UNALLOC_START  = 0x1000;  // spill region start (unused now)

// NOTE: Because of how the MEM stage counts mem_rem down
// (we only move to WB when mem_rem <= 0 on a *later* cycle),
// the *effective* MEM latency is (MEM_LATENCY + 1) cycles.
// Setting this to 1 → effective 2-cycle loads/stores.
constexpr int      MEM_LATENCY    = 1;

uint8_t RAM[RAM_SIZE] = {0};

// 32-BIT READ/WRITE (LITTLE-ENDIAN)
void write32(uint32_t addr, uint32_t val) {
    if (addr + 3 >= RAM_SIZE) return;
    RAM[addr + 0] = (val >> 0)  & 0xFF;
    RAM[addr + 1] = (val >> 8)  & 0xFF;
    RAM[addr + 2] = (val >> 16) & 0xFF;
    RAM[addr + 3] = (val >> 24) & 0xFF;
}

uint32_t read32(uint32_t addr) {
    if (addr + 3 >= RAM_SIZE) return 0;
    uint32_t v = 0;
    v |= (uint32_t(RAM[addr + 0]) << 0);
    v |= (uint32_t(RAM[addr + 1]) << 8);
    v |= (uint32_t(RAM[addr + 2]) << 16);
    v |= (uint32_t(RAM[addr + 3]) << 24);
    return v;
}

// RAM INITIALIZATION
// Fill arrays A and B with random floats, zero C
void init_RAM() {
    random_device rd;
    mt19937 gen(rd());
    uniform_real_distribution<float> dist(-10.0f, 10.0f);

    // Store base pointers
    write32(ARRAY_A_START, ARRAY_A_START + 4);
    write32(ARRAY_B_START, ARRAY_B_START + 4);
    write32(ARRAY_C_START, ARRAY_C_START + 4);

    // Fill A data starting at ARRAY_A_START + 4
    for (uint32_t a = ARRAY_A_START + 4; a <= ARRAY_A_END; a += 4) {
        float f = dist(gen);
        uint32_t bits; memcpy(&bits, &f, 4);
        write32(a, bits);
    }

    // Fill B data
    for (uint32_t b = ARRAY_B_START + 4; b <= ARRAY_B_END; b += 4) {
        float f = dist(gen);
        uint32_t bits; memcpy(&bits, &f, 4);
        write32(b, bits);
    }

    // Zero C data
    for (uint32_t c = ARRAY_C_START + 4; c <= ARRAY_C_END; c += 4) {
        write32(c, 0);
    }
}


// DECODE STRUCTURE
struct Decoded {
    uint32_t raw{};
    uint8_t  opcode{}, rd{}, rs1{}, rs2{}, funct3{}, funct7{};
    int32_t  imm{};
    string   type;      // "I","R","LD",...

    bool is_fp      = false;
    bool is_load    = false;
    bool is_store   = false;
    bool writes_int = false;
    bool writes_fp  = false;

    // Printable mnemonic (addi, lw, flw, fadd.s, blt, ...)
    string name;
};

int32_t signext(uint32_t v, int bits) {
    int32_t m = 1u << (bits - 1);
    return (int32_t)((v ^ m) - m);
}

// helper to pick a mnemonic from decoded fields
string pickMnemonic(const Decoded &d) {
    switch (d.opcode) {
        case 0b0010011: // I-type ALU
            if (d.funct3 == 0b000) return "addi";  // also used for mv
            if (d.funct3 == 0b001) return "slli";
            break;
        case 0b0110011: // R-type
            if (d.funct3 == 0 && d.funct7 == 0) return "add";
            break;
        case 0b0000011: // integer load
            if (d.funct3 == 0b010) return "lw";
            break;
        case 0b0100011: // integer store
            if (d.funct3 == 0b010) return "sw";
            break;
        case 0b0110111:
            return "lui";
        case 0b0000111: // FP load
            if (d.funct3 == 0b010) return "flw";
            break;
        case 0b0100111: // FP store
            if (d.funct3 == 0b010) return "fsw";
            break;
        case 0b1010011: // FP R-type
            if (d.funct7 == 0 && d.funct3 == 0) return "fadd.s";
            break;
        case 0b1100011: // branch
            if (d.funct3 == 0b100) return "blt";
            break;
        case 0b1101111:
            return "jal";    // used for 'j' in asm
        case 0b1100111:
            return "jalr";   // used for ret
        default:
            break;
    }
    // fallback to generic type
    return d.type;
}

// DECODE FUNCTION
Decoded decode(uint32_t inst) {
    Decoded d;
    d.raw    = inst;
    d.opcode = inst & 0x7F;
    d.rd     = (inst >> 7)  & 0x1F;
    d.funct3 = (inst >> 12) & 0x07;
    d.rs1    = (inst >> 15) & 0x1F;
    d.rs2    = (inst >> 20) & 0x1F;
    d.funct7 = (inst >> 25) & 0x7F;

    uint32_t op = d.opcode;
    d.imm = 0;

    if (op == 0b0010011) {
        // addi, slli etc.
        d.imm = signext(inst >> 20, 12);
    }
    else if (op == 0b0000011 || op == 0b0000111) {
        // lw, flw  (SIGNED offset)
        d.imm = signext(inst >> 20, 12);
    }
    else if (op == 0b1100111) {
        // jalr
        d.imm = signext(inst >> 20, 12);
    }
    else if (op == 0b0100011 || op == 0b0100111) {
        // S-type (sw, fsw) (signed)
        uint32_t imm11_5 = (inst >> 25) & 0x7F;
        uint32_t imm4_0  = (inst >> 7)  & 0x1F;
        uint32_t uimm    = (imm11_5 << 5) | imm4_0;
        d.imm = signext(uimm, 12);
    }
    else if (op == 0b0110111) {
        // U-type
        d.imm = (int32_t)(inst & 0xFFFFF000u);
    } else if (op == 0b1100011) {
        // B-type
        uint32_t imm12   = (inst >> 31) & 1;
        uint32_t imm10_5 = (inst >> 25) & 0x3F;
        uint32_t imm4_1  = (inst >> 8)  & 0xF;
        uint32_t imm11   = (inst >> 7)  & 1;
        uint32_t uimm = (imm12 << 12) | (imm11 << 11) |
                        (imm10_5 << 5) | (imm4_1 << 1);
        d.imm = signext(uimm, 13);
    } else if (op == 0b1101111) {
        // J-type
        uint32_t imm20    = (inst >> 31) & 1;
        uint32_t imm10_1  = (inst >> 21) & 0x3FF;
        uint32_t imm11    = (inst >> 20) & 1;
        uint32_t imm19_12 = (inst >> 12) & 0xFF;

        uint32_t uimm = (imm20 << 20) | (imm19_12 << 12) |
                        (imm11 << 11) | (imm10_1 << 1);
        d.imm = signext(uimm, 21);
    }

    switch (d.opcode) {
        case 0b0110011: d.type="R";   d.writes_int=true; break;
        case 0b0010011: d.type="I";   d.writes_int=true; break;
        case 0b0000011: d.type="LD";  d.is_load=true; d.writes_int=true; break;
        case 0b0100011: d.type="ST";  d.is_store=true; break;
        case 0b0000111: d.type="FLW"; d.is_fp=true; d.is_load=true; d.writes_fp=true; break;
        case 0b0100111: d.type="FSW"; d.is_fp=true; d.is_store=true; break;
        case 0b1010011: d.type="FPR"; d.is_fp=true; d.writes_fp=true; break;
        case 0b0110111: d.type="LUI"; d.writes_int=true; break;
        case 0b1100111: d.type="JALR";d.writes_int=true; break;
        case 0b1101111: d.type="JAL"; d.writes_int=true; break;
        case 0b1100011: d.type="BR";  break;
        default:        d.type="UNK"; break;
    }

    d.name = pickMnemonic(d);
    return d;
}

// LATENCY + PIPE STRUCTS
//
// NOTE: Because of the ordering in the main loop, ex_rem and mem_rem
// give an *effective* latency of (value + 1) cycles. So here we
// return "extra cycles", not total:
//
// int ops: effective EX = 1 cycle  -> exLatency = 0
// FP ops : effective EX = 5 cycles -> exLatency = 4
// loads/stores: effective MEM = 2 cycles -> MEM_LATENCY=1
int exLatency(const Decoded &d){ return d.is_fp ? 4 : 0; }
int memLatency(const Decoded &d){ return (d.is_load || d.is_store)? MEM_LATENCY : 0; }

struct InFlight {
    int id{};
    Decoded d;
    int ex_rem{};
    int mem_rem{};
    string tag;        // old type tag (R/I/LD/...)
    string mnemonic;   // real name (addi, lw, flw, ...)

    uint32_t mem_addr = 0;
    bool     mem_addr_valid = false;

    uint32_t intResult = 0;
    uint32_t fpResult  = 0;
};

struct Pipe {
    optional<InFlight> IF, ID, EX, MEM, WB;
};

struct Scoreboard {
    bool intBusy[32]{};
    bool fpBusy[32]{};
};

// REGISTER FILES
uint32_t xreg[32] = {0};
uint32_t freg[32] = {0};

// SCOREBOARD HELPERS
void reserveDest(const Decoded &d, Scoreboard &sb){
    if (d.writes_int && d.rd) sb.intBusy[d.rd] = true;
    if (d.writes_fp  && d.rd) sb.fpBusy[d.rd]  = true;
}

void releaseDest(const Decoded &d, Scoreboard &sb){
    if (d.writes_int && d.rd) sb.intBusy[d.rd] = false;
    if (d.writes_fp  && d.rd) sb.fpBusy[d.rd]  = false;
}

bool sourcesReady(const Decoded &d, const Scoreboard &sb){
    // Integer deps
    if (d.rs1 && sb.intBusy[d.rs1]) return false;
    if (d.rs2 && sb.intBusy[d.rs2]) return false;

    // Floating-point deps (for FP instructions)
    if (d.is_fp) {
        if (d.rs1 && sb.fpBusy[d.rs1]) return false;
        if (d.rs2 && sb.fpBusy[d.rs2]) return false;
    }
    return true;
}


string trim(const string& s){
    size_t i=0, j=s.size();
    while(i<j && isspace((unsigned char)s[i])) ++i;
    while(j>i && isspace((unsigned char)s[j-1])) --j;
    return s.substr(i, j-i);
}

// ASSEMBLER HELPERS
uint32_t encodeR(uint8_t funct7, uint8_t rs2, uint8_t rs1,
                 uint8_t funct3, uint8_t rd, uint8_t opcode) {
    return (uint32_t(funct7) << 25) | (uint32_t(rs2) << 20) |
           (uint32_t(rs1) << 15)   | (uint32_t(funct3) << 12) |
           (uint32_t(rd)  << 7)    | opcode;
}

uint32_t encodeI(int imm, uint8_t rs1, uint8_t funct3,
                 uint8_t rd, uint8_t opcode) {
    return ((uint32_t(imm) & 0xFFFu) << 20) | (uint32_t(rs1) << 15) |
           (uint32_t(funct3) << 12)         | (uint32_t(rd)  << 7) |
           opcode;
}

uint32_t encodeS(int imm, uint8_t rs2, uint8_t rs1,
                 uint8_t funct3, uint8_t opcode) {
    uint32_t uimm    = uint32_t(imm) & 0xFFFu;
    uint32_t imm11_5 = (uimm >> 5) & 0x7F;
    uint32_t imm4_0  =  uimm       & 0x1F;
    return (imm11_5 << 25) | (uint32_t(rs2) << 20) |
           (uint32_t(rs1) << 15)   | (uint32_t(funct3) << 12) |
           (imm4_0 << 7)           | opcode;
}

uint32_t encodeU(int imm20, uint8_t rd, uint8_t opcode) {
    return (uint32_t(imm20) << 12) | (uint32_t(rd) << 7) | opcode;
}

uint32_t encodeB(int imm, uint8_t rs2, uint8_t rs1,
                 uint8_t funct3, uint8_t opcode) {
    uint32_t uimm   = uint32_t(imm);
    uint32_t imm12  = (uimm >> 12) & 1;
    uint32_t imm10_5= (uimm >> 5)  & 0x3F;
    uint32_t imm4_1 = (uimm >> 1)  & 0xF;
    uint32_t imm11  = (uimm >> 11) & 1;

    return (imm12 << 31)          |
           (imm10_5 << 25)        |
           (uint32_t(rs2) << 20)  |
           (uint32_t(rs1) << 15)  |
           (uint32_t(funct3) << 12) |
           (imm4_1 << 8)          |
           (imm11 << 7)           |
           opcode;
}

uint32_t encodeJ(int imm, uint8_t rd, uint8_t opcode) {
    uint32_t uimm   = uint32_t(imm);
    uint32_t imm20  = (uimm >> 20) & 1;
    uint32_t imm10_1= (uimm >> 1)  & 0x3FF;
    uint32_t imm11  = (uimm >> 11) & 1;
    uint32_t imm19_12= (uimm >> 12) & 0xFF;

    return (imm20 << 31)        |
           (imm19_12 << 12)     |
           (imm11 << 20)        |
           (imm10_1 << 21)      |
           (uint32_t(rd) << 7)  |
           opcode;
}

int regIndex(const string& r) {
    static map<string,int> rmap = {
        {"zero",0},{"ra",1},{"sp",2},{"gp",3},{"tp",4},{"t0",5},{"t1",6},{"t2",7},
        {"s0",8},{"fp",8},{"s1",9},{"a0",10},{"a1",11},{"a2",12},{"a3",13},
        {"a4",14},{"a5",15},{"a6",16},{"a7",17},{"s2",18},{"s3",19},{"s4",20},
        {"s5",21},{"s6",22},{"s7",23},{"s8",24},{"s9",25},{"s10",26},{"s11",27},
        {"t3",28},{"t4",29},{"t5",30},{"t6",31}
    };
    auto it = rmap.find(r);
    if (it == rmap.end()) throw runtime_error("Unknown register: " + r);
    return it->second;
}

int fpRegIndex(const string& r) {
    if (r.size() >= 3 && r[0]=='f' && r[1]=='t') {
        int n = stoi(r.substr(2));
        if (n >= 0 && n < 32) return n;
    }
    throw runtime_error("Unknown FP register: " + r);
}

int parseImmExpr(const string& tok) {
    string t = trim(tok);

    if (t.rfind("%hi(", 0) == 0) {
        auto p = t.find('(');
        auto q = t.find(')', p + 1);
        int val = stoi(t.substr(p + 1, q - p - 1), nullptr, 0);
        int hi20 = (val + 0x800) >> 12;  // RISC-V hi rule
        return hi20;
    }

    if (t.rfind("%lo(", 0) == 0) {
        auto p = t.find('(');
        auto q = t.find(')', p + 1);
        int val = stoi(t.substr(p + 1, q - p - 1), nullptr, 0);
        int hi20 = (val + 0x800) >> 12;
        int lo12 = val - (hi20 << 12);   // in [-2048, 2047]
        return lo12;
    }

    return stoi(t, nullptr, 0);
}


optional<uint32_t> assembleLine(const string& raw,
                                int pc,
                                const map<string,int>& labels) {
    string s = raw;
    auto hash = s.find('#');
    if (hash != string::npos) s = s.substr(0, hash);
    s = trim(s);
    if (s.empty()) return nullopt;

    string rest = s;
    auto col = s.find(':');
    if (col != string::npos) {
        rest = trim(s.substr(col+1));
        if (rest.empty()) return nullopt;
    }

    for (char& c : rest) if (c == ',') c = ' ';

    stringstream ss(rest);
    string op; ss >> op;
    if (op.empty()) return nullopt;

    if (op == "addi") {
        string rd, rs1, imm;
        ss >> rd >> rs1 >> imm;
        return encodeI(stoi(imm), regIndex(rs1), 0b000, regIndex(rd), 0b0010011);
    }

    if (op == "mv") {
        string rd, rs1;
        ss >> rd >> rs1;
        return encodeI(0, regIndex(rs1), 0b000, regIndex(rd), 0b0010011);
    }

    if (op == "lw") {
        string rd, addr;
        ss >> rd >> addr;
        auto close = addr.rfind(')');
        auto open  = addr.rfind('(', (close==string::npos? string::npos: close));
        if (open == string::npos || close == string::npos)
            throw runtime_error("Bad lw address: " + addr);
        string offsetExpr = addr.substr(0, open);
        string baseReg    = addr.substr(open+1, close-open-1);
        int offset = parseImmExpr(offsetExpr);
        return encodeI(offset, regIndex(baseReg), 0b010, regIndex(rd), 0b0000011);
    }

    if (op == "sw") {
        string rs2, addr;
        ss >> rs2 >> addr;
        auto close = addr.rfind(')');
        auto open  = addr.rfind('(', (close==string::npos? string::npos: close));
        if (open == string::npos || close == string::npos)
            throw runtime_error("Bad sw address: " + addr);
        string offsetExpr = addr.substr(0, open);
        string baseReg    = addr.substr(open+1, close-open-1);
        int offset = parseImmExpr(offsetExpr);
        return encodeS(offset, regIndex(rs2), regIndex(baseReg), 0b010, 0b0100011);
    }

    if (op == "lui") {
        string rd, immExpr;
        ss >> rd >> immExpr;
        int hi = parseImmExpr(immExpr);
        return encodeU(hi, regIndex(rd), 0b0110111);
    }

    if (op == "slli") {
        string rd, rs1, sh;
        ss >> rd >> rs1 >> sh;
        int shamt = stoi(sh) & 0x1F;
        return encodeI(shamt, regIndex(rs1), 0b001, regIndex(rd), 0b0010011);
    }

    if (op == "add") {
        string rd, rs1, rs2;
        ss >> rd >> rs1 >> rs2;
        return encodeR(0b0000000, regIndex(rs2), regIndex(rs1),
                       0b000, regIndex(rd), 0b0110011);
    }

    if (op == "flw") {
        string rd, addr;
        ss >> rd >> addr;
        auto close = addr.rfind(')');
        auto open  = addr.rfind('(', (close==string::npos? string::npos: close));
        if (open == string::npos || close == string::npos)
            throw runtime_error("Bad flw address: " + addr);
        string offsetExpr = addr.substr(0, open);
        string baseReg    = addr.substr(open+1, close-open-1);
        int offset = parseImmExpr(offsetExpr);
        return encodeI(offset, regIndex(baseReg), 0b010, fpRegIndex(rd), 0b0000111);
    }

    if (op == "fsw") {
        string rs2, addr;
        ss >> rs2 >> addr;
        auto close = addr.rfind(')');
        auto open  = addr.rfind('(', (close==string::npos? string::npos: close));
        if (open == string::npos || close == string::npos)
            throw runtime_error("Bad fsw address: " + addr);
        string offsetExpr = addr.substr(0, open);
        string baseReg    = addr.substr(open+1, close-open-1);
        int offset = parseImmExpr(offsetExpr);
        return encodeS(offset, fpRegIndex(rs2), regIndex(baseReg), 0b010, 0b0100111);
    }

    if (op == "fadd.s") {
        string rd, rs1, rs2;
        ss >> rd >> rs1 >> rs2;
        return encodeR(0b0000000, fpRegIndex(rs2), fpRegIndex(rs1),
                       0b000, fpRegIndex(rd), 0b1010011);
    }

    if (op == "blt") {
        string rs1, rs2, label;
        ss >> rs1 >> rs2 >> label;
        auto it = labels.find(label);
        if (it == labels.end()) throw runtime_error("Unknown label: " + label);
        int target = it->second;
        int offset = target - pc;
        return encodeB(offset, regIndex(rs2), regIndex(rs1), 0b100, 0b1100011);
    }

    if (op == "j") {
        string label;
        ss >> label;
        auto it = labels.find(label);
        if (it == labels.end()) throw runtime_error("Unknown label: " + label);
        int target = it->second;
        int offset = target - pc;
        return encodeJ(offset, 0, 0b1101111); // jal x0, offset
    }

    if (op == "ret") {
        return 0x00008067; // jalr x0, ra, 0
    }

    throw runtime_error("Unsupported assembly: " + op);
}

// MEM-PORT LABELING (for table)
string memPortFromAddr(uint32_t addr, bool isIF) {
    char buf[64];

    if (isIF) {
        // Instruction fetch region
        if (addr <= 0x0093) { sprintf(buf, "I:0x%04X", addr); return buf; }
        if (addr <= 0x01FF) { sprintf(buf, "I:0x%04X", addr); return buf; }
        sprintf(buf, "U:0x%04X", addr);
        return buf;
    }

    // Data port: classify by address range
    if (addr >= STACK_START && addr <= STACK_END) {
        sprintf(buf, "D:0x%04X", addr); return buf;
    }
    if (addr >= ARRAY_A_START && addr <= ARRAY_A_END) {
        sprintf(buf, "A:0x%04X", addr); return buf;
    }
    if (addr >= ARRAY_B_START && addr <= ARRAY_B_END) {
        sprintf(buf, "B:0x%04X", addr); return buf;
    }
    if (addr >= ARRAY_C_START && addr <= ARRAY_C_END) {
        sprintf(buf, "C:0x%04X", addr); return buf;
    }

    sprintf(buf, "U:0x%04X", addr);
    return buf;
}

// EX STAGE SETUP
void setupEX(InFlight &f) {
    const Decoded &d = f.d;
    uint32_t op = d.opcode;

    f.intResult = 0;
    f.fpResult  = 0;

    // I-type ALU (addi, slli)
    if (op == 0b0010011) {
        if (d.funct3 == 0b000) {        // addi / mv
            f.intResult = xreg[d.rs1] + (int32_t)d.imm;
        } else if (d.funct3 == 0b001) { // slli
            uint32_t shamt = (f.d.raw >> 20) & 0x1F;
            f.intResult = xreg[d.rs1] << shamt;
        }
    }
    else if (op == 0b0110011) {       // R-type add
        if (d.funct3 == 0 && d.funct7 == 0) {
            f.intResult = xreg[d.rs1] + xreg[d.rs2];
        }
    }
    else if (op == 0b0110111) {       // LUI
        f.intResult = (uint32_t)d.imm;
    }
    // JAL/JALR link value could be set here if PC tracked.

    // Address generation for loads/stores:
    if (d.is_load) {
        uint32_t base = xreg[d.rs1];
        int32_t  off  = d.imm;
        uint32_t ea   = base + off;
        f.mem_addr = ea;
        f.mem_addr_valid = true;
    } else if (d.is_store) {
        uint32_t base = xreg[d.rs1];
        int32_t  off  = d.imm;
        uint32_t ea   = base + off;
        f.mem_addr = ea;
        f.mem_addr_valid = true;
    }

    // FP add (fadd.s)
    if (op == 0b1010011 && d.funct7 == 0 && d.funct3 == 0) {
        float a, b, c;
        memcpy(&a, &freg[d.rs1], 4);
        memcpy(&b, &freg[d.rs2], 4);
        c = a + b;
        memcpy(&f.fpResult, &c, 4);
    }
}

// WB EVENT STRUCT FOR LOGGING
struct WBEvent {
    int      cycle;
    string   instr;    // mnemonic
    int      rd;
    int32_t  decVal;
    uint32_t hexVal;
    bool     isFp;
    bool     isSp;
};


//MAIN
int main() {
    ios::sync_with_stdio(false);
    cin.tie(nullptr);
    cout.setf(ios::unitbuf);

    init_RAM();

    // Initial integer register state
    xreg[0] = 0;         // x0 hard-wired
    xreg[2] = 0;         // sp will be set from .sp or default
    xreg[8] = 0;         // s0 / fp

    cout << "=== RISC-V Pipeline Simulator ===\n";
    cout << "Loading and assembling CPU0.txt, then running pipeline...\n";

    //Load assembly files
    ifstream fin("CPU0.txt");
    if (!fin.is_open()) {
        cerr << "ERROR: Could not open CPU0.txt\n";
        return 0;
    }

    vector<string> lines;
    string line;
    while (getline(fin, line)) {
        lines.push_back(line);
    }
    fin.close();

    // First pass, collect labels
    map<string,int> labels;
    int pc = 0; // byte address
    for (const auto &raw : lines) {
        string s = raw;
        auto hash = s.find('#');
        if (hash != string::npos) s = s.substr(0, hash);
        s = trim(s);
        if (s.empty()) continue;

        string rest = s;
        auto col = s.find(':');
        if (col != string::npos) {
            string label = trim(s.substr(0, col));
            if (!label.empty()) labels[label] = pc;
            rest = trim(s.substr(col + 1));
        }

        if (rest.empty()) continue;

        // Directives do not advance PC
        if (rest[0] == '.') continue;

        pc += 4;
    }

    // Second pass: assemble + .sp directive 
    vector<Decoded> program;
    pc = 0;
    for (const auto &raw : lines) {
        try {
            string s = raw;
            auto hash = s.find('#');
            if (hash != string::npos) s = s.substr(0, hash);
            s = trim(s);
            if (s.empty()) continue;

            string rest = s;
            auto col = s.find(':');
            if (col != string::npos) {
                rest = trim(s.substr(col + 1));
            }
            if (rest.empty()) continue;

            // Directives
            if (rest[0] == '.') {
                if (rest.rfind(".sp", 0) == 0) {
                    string val = trim(rest.substr(3));
                    if (!val.empty()) {
                        uint32_t spVal = static_cast<uint32_t>(stoi(val, nullptr, 0));
                        xreg[2] = spVal;  // last .sp wins
                    }
                }
                continue;
            }

            auto instOpt = assembleLine(raw, pc, labels);
            if (instOpt) {
                uint32_t inst = *instOpt;
                Decoded d = decode(inst);
                program.push_back(d);
                pc += 4;
            }
        } catch (const exception &e) {
            cerr << "Assembler error: " << e.what() << " in line: " << raw << "\n";
        }
    }

    // Default SP if no .sp: top of stack, 4-byte aligned
    if (xreg[2] == 0) {
        uint32_t sp_default = STACK_END & ~0x3u; // 0x02FF -> 0x02FC
        xreg[2] = sp_default;
    }
    xreg[8] = xreg[2];   // s0/fp

    if (program.empty()) {
        cout << "No valid instructions assembled.\n";
        return 0;
    }

    // Set up pipeline
    Pipe pipe;
    Scoreboard sb{};
    int cycle = 0;
    bool done = false;
    bool halted = false;
    const int MAX_CYCLES = 200000;  // safety cap

    uint32_t PC = 0;  // byte address into program[]

    vector<WBEvent> wbDiag;
    int32_t lastSpVal = static_cast<int32_t>(xreg[2]);

    // column widths
    const int IF_W      = 10;
    const int ID_W      = 32;
    const int EX_W      = 26;
    const int MEM_W     = 26;
    const int WB_W      = 10;
    const int MEMPORT_W = 18;

    auto pad = [](const string &s, int width) {
        if ((int)s.size() >= width) return s.substr(0, width);
        return s + string(width - (int)s.size(), ' ');
    };

    cout << "Cycle | " << setw(IF_W) << left << "IF"
         << " | "   << setw(ID_W)   << "ID"
         << " | "   << setw(EX_W)   << "EX"
         << " | "   << setw(MEM_W)  << "MEM"
         << " | "   << setw(WB_W)   << "WB"
         << " | "   << setw(MEMPORT_W) << "MEMPORT"
         << " | "   << setw(10)     << "SP(hex)"
         << " | "   << setw(7)      << "SP(dec)"
         << "\n";

    cout << string(5 + 3 + IF_W + 3 + ID_W + 3 + EX_W + 3 + MEM_W +
                   3 + WB_W + 3 + MEMPORT_W + 3 + 10 + 3 + 7, '-')
         << "\n";

    while (!done && cycle < MAX_CYCLES) {
        ++cycle;

        //WRITEBACK

        if (pipe.WB) {
            InFlight &w = *pipe.WB;
            const Decoded &d = w.d;

            int rd = d.rd;
            uint32_t writeHex = 0;
            bool doWriteInt = false;
            bool doWriteFp  = false;

            // LOADS
            if (d.is_load) {
                uint32_t loaded = read32(w.mem_addr);
                if (d.opcode == 0b0000011 && rd != 0) { // lw
                    writeHex   = loaded;
                    doWriteInt = true;
                } else if (d.opcode == 0b0000111) {     // flw
                    writeHex   = loaded;
                    doWriteFp  = true;
                }
            }
            // INTEGER ALU / LUI / JAL/JALR
            else if (d.writes_int && rd != 0) {
                writeHex   = w.intResult;
                doWriteInt = true;
            }
            // FP ALU
            else if (d.writes_fp) {
                writeHex   = w.fpResult;
                doWriteFp  = true;
            }

            // Log WB event
            if (doWriteInt || doWriteFp) {
                bool isFpWrite = doWriteFp;
                bool isSpWrite = (rd == 2);

                int32_t decVal;
                if (isSpWrite) {
                    int32_t newSp = static_cast<int32_t>(writeHex);
                    decVal = newSp - lastSpVal; // show delta for SP (e.g., -16)
                    lastSpVal = newSp;
                } else {
                    decVal = static_cast<int32_t>(writeHex);
                }

                WBEvent e;
                e.cycle = cycle;
                e.instr = w.mnemonic;
                e.rd    = rd;
                e.decVal= decVal;
                e.hexVal= writeHex;
                e.isFp  = isFpWrite;
                e.isSp  = isSpWrite;
                wbDiag.push_back(e);
            }

            // Actually write registers
            if (doWriteInt && rd != 0) {
                xreg[rd] = writeHex;
            }
            if (doWriteFp) {
                freg[rd] = writeHex;
            }

            releaseDest(d, sb);
            pipe.WB.reset();
        }

        // MEM -> WB (STORE completes here only)
        optional<InFlight> promoteToWB;

        if (pipe.MEM && pipe.MEM->mem_rem <= 0) {
            InFlight memInst = *pipe.MEM;
            const Decoded &d = memInst.d;

            if (d.is_store) {
                if (d.opcode == 0b0100011) write32(memInst.mem_addr, xreg[d.rs2]); // sw
                if (d.opcode == 0b0100111) write32(memInst.mem_addr, freg[d.rs2]); // fsw
                pipe.MEM.reset();
            }
            else {
                promoteToWB = memInst;
                pipe.MEM.reset();
            }
        }

        if (promoteToWB && !pipe.WB) {
            pipe.WB = promoteToWB;
        }

        //               EX -> MEM OR EX -> WB
        if (pipe.EX && pipe.EX->ex_rem <= 0) {

            InFlight exInst = *pipe.EX;
            const Decoded &d = exInst.d;

            // control-flow handling: branch/jump update PC + flush 
            uint32_t curPC = static_cast<uint32_t>(exInst.id) * 4;

            if (d.opcode == 0b1100011) { // branches
                if (d.funct3 == 0b100) { // blt
                    int32_t v1 = static_cast<int32_t>(xreg[d.rs1]);
                    int32_t v2 = static_cast<int32_t>(xreg[d.rs2]);
                    if (v1 < v2) {
                        PC = curPC + d.imm;
                        // flush younger instructions
                        pipe.IF.reset();
                        pipe.ID.reset();
                    }
                }
            } else if (d.opcode == 0b1101111) { // jal (used as 'j')
                uint32_t target = curPC + d.imm;
                PC = target;
                pipe.IF.reset();
                pipe.ID.reset();
            } else if (d.opcode == 0b1100111) { // jalr (used for ret)
                uint32_t target = (xreg[d.rs1] + d.imm) & ~1u;
                PC = target;
                pipe.IF.reset();
                pipe.ID.reset();

                // Canonical RISC-V ret = jalr x0, ra, 0
                if (d.raw == 0x00008067) {
                    halted = true;  // signal termination
                }
            }

            // normal EX stage promotion
            if (d.is_load || d.is_store) {
                if (!pipe.MEM) {
                    pipe.MEM = exInst;
                    pipe.EX.reset();
                }
            }
            else if (d.writes_int || d.writes_fp) {
                if (!pipe.WB) {
                    pipe.WB = exInst;
                    pipe.EX.reset();
                }
            }
            else {
                pipe.EX.reset();
            }
        }

        // COUNTDOWN TIMERS
        if (pipe.EX  && pipe.EX->ex_rem  > 0) pipe.EX->ex_rem--;
        if (pipe.MEM && pipe.MEM->mem_rem > 0) pipe.MEM->mem_rem--;

        // ID -> EX
        bool   stall       = false;
        string stallReason;

        if (pipe.ID) {
            bool srcReady = sourcesReady(pipe.ID->d, sb);

            if (!srcReady || pipe.EX) {
                stall = true;

                const Decoded &dID = pipe.ID->d;
                if (!srcReady) {
                    if (dID.rs1 && sb.intBusy[dID.rs1])      stallReason = "rs1 busy";
                    else if (dID.rs2 && sb.intBusy[dID.rs2]) stallReason = "rs2 busy";
                    else                                     stallReason = "src busy";
                } else if (pipe.EX) {
                    stallReason = "EX busy";
                }
            } else {
                pipe.EX = pipe.ID;
                reserveDest(pipe.ID->d, sb);
                setupEX(*pipe.EX);
                pipe.ID.reset();
            }
        }

        // IF -> ID
        if (!stall && pipe.IF) {
            pipe.ID = pipe.IF;
            pipe.IF.reset();
        }

        // FETCH NEW INSTRUCTION (PC-based)
        if (!halted && !pipe.IF && (PC / 4) < program.size()) {

            InFlight f;
            f.id       = static_cast<int>(PC / 4);
            f.d        = program[PC / 4];
            f.ex_rem   = exLatency(f.d);
            f.mem_rem  = memLatency(f.d);
            f.tag      = f.d.type;
            f.mnemonic = f.d.name;
            pipe.IF = f;

            // default fall-through increment
            PC += 4;
        }

        // PRINT PIPELINE ROW
        string IFs;
        if (pipe.IF) IFs = pad(pipe.IF->mnemonic, IF_W);
        else         IFs = pad(".", IF_W);

        string IDs;
        if (pipe.ID) {
            string base = pipe.ID->mnemonic;
            if (stall) {
                base += " (STALL";
                if (!stallReason.empty()) base += ": " + stallReason;
                base += ")";
            }
            IDs = pad(base, ID_W);
        } else {
            IDs = pad(".", ID_W);
        }

        string EXs;
        if (pipe.EX) {
            int rem = pipe.EX->ex_rem;
            if (rem < 0) rem = 0;
            string base = pipe.EX->mnemonic + " (" + to_string(rem) + " cyc left)";
            EXs = pad(base, EX_W);
        } else {
            EXs = pad(".", EX_W);
        }

        string MEMs;
        if (pipe.MEM) {
            int rem = pipe.MEM->mem_rem;
            if (rem < 0) rem = 0;
            string base = pipe.MEM->mnemonic + " (" + to_string(rem) + " cyc left)";
            MEMs = pad(base, MEM_W);
        } else {
            MEMs = pad(".", MEM_W);
        }

        string WBs;
        if (pipe.WB) WBs = pad(pipe.WB->mnemonic, WB_W);
        else         WBs = pad(".", WB_W);

        string memport = ".";
        // IF port (instruction fetch)
        if (pipe.IF) {
            uint32_t pcaddr = static_cast<uint32_t>(pipe.IF->id) * 4;
            memport = memPortFromAddr(pcaddr, true);
        }

        // MEM port (data)
        if (pipe.MEM) {
            const InFlight &f = *pipe.MEM;
            if ((f.d.is_load || f.d.is_store) && f.mem_addr_valid) {
                string port = memPortFromAddr(f.mem_addr, false);

                if (f.mem_addr >= ARRAY_A_START && f.mem_addr <= ARRAY_A_END)
                    port += " [A]";
                else if (f.mem_addr >= ARRAY_B_START && f.mem_addr <= ARRAY_B_END)
                    port += " [B]";
                else if (f.mem_addr >= ARRAY_C_START && f.mem_addr <= ARRAY_C_END)
                    port += " [C]";
                else if (f.mem_addr >= STACK_START && f.mem_addr <= STACK_END)
                    port += " [STACK]";
                else if (f.mem_addr >= UNALLOC_START)
                    port += " [UNALLOC]";

                memport = port;
            }
        }

        cout << setw(5) << right << cycle << " | "
             << IFs  << " | "
             << IDs  << " | "
             << EXs  << " | "
             << MEMs << " | "
             << WBs  << " | "
             << setw(MEMPORT_W) << left << memport << " | "
             << "0x" << hex << setw(8) << setfill('0') << xreg[2]
             << dec << setfill(' ') << " | "
             << setw(7) << (int32_t)xreg[2]
             << "\n";

        // done check
        bool drain = !pipe.IF && !pipe.ID && !pipe.EX && !pipe.MEM && !pipe.WB;
        bool noMore = halted || (PC / 4 >= program.size());
        done = noMore && drain;
    }

    cout << "--------------------------------------------------------------------\n";
    cout << "Completed after " << cycle << " cycles.\n";

    // PRINT STACK POINTER & STACK FRAME VALUES
    cout << "\n=== STACK STATE ===\n";
    uint32_t finalSP = xreg[2];
    cout << "Final SP (x2) = 0x" << hex << finalSP << dec << "\n";

    uint32_t frameBase = finalSP;

    cout << "Assumed stack frame base (SP-16) = 0x" << hex << frameBase << dec << "\n";

    cout << "Frame words (offsets 0, 4, 8, 12):\n";
    for (int i = 0; i < 4; ++i) {
        uint32_t addr = frameBase + i*4;
        uint32_t val  = read32(addr);
        cout << "  [0x" << hex << addr << "] = 0x" << setw(8) << setfill('0') << val
             << dec << setfill(' ');
        if (i == 0) cout << "   (local at sp)";
        if (i == 1) cout << "   (local at sp+4)";
        if (i == 2) cout << "   (saved s0 @ sp+8)";
        if (i == 3) cout << "   (saved ra @ sp+12)";
        cout << "\n";
    }

    //        RAM SAMPLES FROM A, B, C REGION
    // First, read the base pointers stored at 0x0400, 0x0800, 0x0C00
    uint32_t ptrA = read32(ARRAY_A_START);
    uint32_t ptrB = read32(ARRAY_B_START);
    uint32_t ptrC = read32(ARRAY_C_START);

    cout << "\nArray base pointers (CPU0 layout):\n";
    cout << "  *A base ptr* @ 0x" << hex << ARRAY_A_START
         << " = 0x" << setw(8) << setfill('0') << ptrA << dec << "\n";
    cout << "  *B base ptr* @ 0x" << hex << ARRAY_B_START
         << " = 0x" << hex << setw(8) << setfill('0') << ptrB << dec << "\n";
    cout << "  *C base ptr* @ 0x" << hex << ARRAY_C_START
         << " = 0x" << hex << setw(8) << setfill('0') << ptrC << dec << "\n";
    cout << setfill(' ');

    // Now read the actual first elements A[0], B[0], C[0] using those pointers
    uint32_t rawA0 = read32(ptrA);
    uint32_t rawB0 = read32(ptrB);
    uint32_t rawC0 = read32(ptrC);

    float a0, b0, c0;
    memcpy(&a0, &rawA0, 4);
    memcpy(&b0, &rawB0, 4);
    memcpy(&c0, &rawC0, 4);

    cout << "\nRAM Sample (first elements):\n";
    cout << "  A[0] @ 0x" << hex << ptrA << " = "
         << dec << fixed << setprecision(2) << a0 << "\n";
    cout << "  B[0] @ 0x" << hex << ptrB << " = "
         << dec << fixed << setprecision(2) << b0 << "\n";
    cout << "  C[0] @ 0x" << hex << ptrC << " = "
         << dec << fixed << setprecision(2) << c0 << " (sum output region)\n";


    return 0;
}
