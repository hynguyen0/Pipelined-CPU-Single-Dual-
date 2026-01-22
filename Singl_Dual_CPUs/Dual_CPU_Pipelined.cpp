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

// RAM & CONSTANTS
constexpr uint32_t RAM_SIZE       = 0x1400;  // 0x0000–0x13FF

constexpr uint32_t STACK_START    = 0x0200;
constexpr uint32_t STACK_END      = 0x02FF;

// Hard-coded array mapping
constexpr uint32_t ARRAY_A_START  = 0x0400;  // 1024
constexpr uint32_t ARRAY_A_END    = 0x07FF;  // 2047

constexpr uint32_t ARRAY_B_START  = 0x0800;  // 2048
constexpr uint32_t ARRAY_B_END    = 0x0BFF;  // 3071

constexpr uint32_t ARRAY_C_START  = 0x0C00;  // 3072
constexpr uint32_t ARRAY_C_END    = 0x0FFF;  // 4095

constexpr uint32_t ARRAY_LEN      = 0x0400;  // 1 KB per array
constexpr uint32_t UNALLOC_START  = 0x1000;  // spill region start (unused now)
constexpr int      MEM_LATENCY    = 2;

uint8_t RAM[RAM_SIZE] = {0};

// SAFE 32-BIT READ/WRITE (LITTLE-ENDIAN)
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
//   Fill arrays A and B with random floats, zero C
//   and store base pointers at ARRAY_X_START
void init_RAM() {
    random_device rd;
    mt19937 gen(rd());
    uniform_real_distribution<float> dist(-10.0f, 10.0f);

    // Store base pointers: each array start holds pointer to first element
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
    string   name;
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
            if (d.funct3 == 0 && d.funct7 == 0)          return "add";
            if (d.funct3 == 0 && d.funct7 == 0b0100000)  return "sub";
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
            if (d.funct7 == 0 && d.funct3 == 0)            return "fadd.s";
            if (d.funct7 == 0b0000100 && d.funct3 == 0)    return "fsub.s";
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
        // S-type (sw, fsw)  — SIGNED
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
int exLatency(const Decoded &d){ return d.is_fp ? 5 : 1; }
int memLatency(const Decoded &d){ return (d.is_load || d.is_store)? MEM_LATENCY : 0; }

struct InFlight {
    int id{};
    Decoded d;
    int ex_rem{};
    int mem_rem{};
    string tag;
    string mnemonic;

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

// REGISTER STATE PER CPU
struct CPUState {
    int id = 0;

    // architectural state
    uint32_t x[32]{};
    uint32_t f[32]{};

    // program + control
    vector<Decoded> program;
    uint32_t PC = 0;              // byte address
    uint64_t fetched = 0;
    uint64_t maxFetches = 0;
    bool     halted = false;      // stop fetching
    bool     done   = false;      // pipeline drained

    Pipe       pipe;
    Scoreboard sb;

    // stats
    uint64_t instrCompleted = 0;
    uint64_t stallCount        = 0;
    uint64_t busWaitStall      = 0;
    uint64_t dataHazardStall   = 0;
    uint64_t exBusyStall       = 0;

    bool   stalledThisCycle    = false;
    string stallReasonThisCycle;

    uint64_t finishCycle = 0;
};

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

    if (op == "sub") {
        string rd, rs1, rs2;
        ss >> rd >> rs1 >> rs2;
        return encodeR(0b0100000, regIndex(rs2), regIndex(rs1),
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

    if (op == "fsub.s") {
        string rd, rs1, rs2;
        ss >> rd >> rs1 >> rs2;
        return encodeR(0b0000100, fpRegIndex(rs2), fpRegIndex(rs1),
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
        // Instruction fetch region (simple classification by address)
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

// EX STAGE SETUP (per CPU)
void setupEX(CPUState &cpu, InFlight &f) {
    const Decoded &d = f.d;
    uint32_t op = d.opcode;

    f.intResult = 0;
    f.fpResult  = 0;
    f.mem_addr_valid = false;

    // I-type ALU (addi, slli)
    if (op == 0b0010011) {
        if (d.funct3 == 0b000) {        // addi / mv
            f.intResult = cpu.x[d.rs1] + (int32_t)d.imm;
        } else if (d.funct3 == 0b001) { // slli
            uint32_t shamt = (f.d.raw >> 20) & 0x1F;
            f.intResult = cpu.x[d.rs1] << shamt;
        }
    }
    else if (op == 0b0110011) {       // R-type int add/sub
        if (d.funct3 == 0 && d.funct7 == 0) {
            f.intResult = cpu.x[d.rs1] + cpu.x[d.rs2];
        } else if (d.funct3 == 0 && d.funct7 == 0b0100000) {
            f.intResult = cpu.x[d.rs1] - cpu.x[d.rs2];
        }
    }
    else if (op == 0b0110111) {       // LUI
        f.intResult = (uint32_t)d.imm;
    }

    // Address generation for loads/stores:
    if (d.is_load) {
        uint32_t base = cpu.x[d.rs1];
        int32_t  off  = d.imm;
        uint32_t ea   = base + off;
        f.mem_addr = ea;
        f.mem_addr_valid = true;
        f.mem_rem = memLatency(d);
    } else if (d.is_store) {
        uint32_t base = cpu.x[d.rs1];
        int32_t  off  = d.imm;
        uint32_t ea   = base + off;
        f.mem_addr = ea;
        f.mem_addr_valid = true;
        f.mem_rem = memLatency(d);
    }

    // FP add/sub
    if (op == 0b1010011 && d.funct3 == 0) {
        float a, b, c;
        memcpy(&a, &cpu.f[d.rs1], 4);
        memcpy(&b, &cpu.f[d.rs2], 4);
        if (d.funct7 == 0b0000000)
            c = a + b;
        else if (d.funct7 == 0b0000100)
            c = a - b;
        memcpy(&f.fpResult, &c, 4);
    }
}

// PROGRAM IMAGE LOADER
struct ProgramImage {
    vector<Decoded> instrs;
    uint32_t initialSP = 0;
};

ProgramImage loadProgram(const string &filename) {
    ifstream fin(filename);
    if (!fin.is_open()) {
        cerr << "ERROR: Could not open " << filename << "\n";
        return ProgramImage{};
    }

    vector<string> lines;
    string line;
    while (getline(fin, line)) lines.push_back(line);
    fin.close();

    // First pass: labels
    map<string,int> labels;
    int pc = 0;
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
        if (rest[0] == '.') continue;   // directives do not advance PC

        pc += 4;
    }

    // Second pass: assemble + .sp
    vector<Decoded> program;
    uint32_t spVal = 0;
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

            if (rest[0] == '.') {
                if (rest.rfind(".sp", 0) == 0) {
                    string val = trim(rest.substr(3));
                    if (!val.empty()) {
                        spVal = static_cast<uint32_t>(stoi(val, nullptr, 0));
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
            cerr << "Assembler error: " << e.what()
                 << " in file " << filename
                 << " line: " << raw << "\n";
        }
    }

    if (spVal == 0) {
        spVal = STACK_END & ~0x3u; // default if no .sp
    }

    ProgramImage img;
    img.instrs    = move(program);
    img.initialSP = spVal;
    return img;
}

// MEM BUS ARBITRATION STRUCTS
struct MemRequest {
    bool valid   = false;
    bool isLoad  = false;
    bool isStore = false;
    uint32_t addr = 0;
    int cpuId    = -1;
};

int arbitrateRoundRobin(const MemRequest &r0,
                        const MemRequest &r1,
                        int &lastGranted)
{
    bool c0 = r0.valid;
    bool c1 = r1.valid;

    if (c0 && !c1) { lastGranted = 0; return 0; }
    if (c1 && !c0) { lastGranted = 1; return 1; }
    if (!c0 && !c1) return -1;

    // both valid: round-robin on lastGranted
    if (lastGranted == 1) {
        lastGranted = 0;
        return 0;
    } else {
        lastGranted = 1;
        return 1;
    }
}

// PIPELINE STEPS

// WRITEBACK
void stepWB(CPUState &cpu) {
    if (!cpu.pipe.WB) return;

    InFlight &w = *cpu.pipe.WB;
    const Decoded &d = w.d;
    int rd = d.rd;

    bool doInt = false, doFp = false;
    uint32_t writeVal = 0;

    if (d.is_load) {
        if (d.opcode == 0b0000011 && rd != 0) { // lw
            writeVal = w.intResult;
            doInt = true;
        } else if (d.opcode == 0b0000111) {     // flw
            writeVal = w.fpResult;
            doFp = true;
        }
    } else if (d.writes_int && rd != 0) {
        writeVal = w.intResult;
        doInt = true;
    } else if (d.writes_fp) {
        writeVal = w.fpResult;
        doFp = true;
    }

    if (doInt && rd != 0) cpu.x[rd] = writeVal;
    if (doFp)             cpu.f[rd] = writeVal;

    releaseDest(d, cpu.sb);
    cpu.pipe.WB.reset();
    cpu.instrCompleted++;
}

// MEM (with bus grant flag)  
void stepMEM(CPUState &cpu, bool busGranted) {
    if (!cpu.pipe.MEM) return;

    InFlight &f = *cpu.pipe.MEM;
    const Decoded &d = f.d;

    if (!(d.is_load || d.is_store)) {
        // non-memory op in MEM should just flow to WB
        if (!cpu.pipe.WB) {
            cpu.pipe.WB = cpu.pipe.MEM;
            cpu.pipe.MEM.reset();
        }
        return;
    }

    if (!busGranted) {
        cpu.busWaitStall++;
        cpu.stallCount++;
        return;
    }

    if (f.mem_rem > 0) {
        f.mem_rem--;
        if (f.mem_rem > 0) return;
    }

    // mem_rem just reached 0: perform the access
    if (d.is_store) {
        if (d.opcode == 0b0100011) {
            write32(f.mem_addr, cpu.x[d.rs2]);
        } else if (d.opcode == 0b0100111) {
            write32(f.mem_addr, cpu.f[d.rs2]);
        }
        releaseDest(d, cpu.sb);
        cpu.pipe.MEM.reset();
        cpu.instrCompleted++;
    } else {
        uint32_t loaded = read32(f.mem_addr);
        if (d.opcode == 0b0000011) {
            f.intResult = loaded;
        } else if (d.opcode == 0b0000111) {
            f.fpResult = loaded;
        }
        if (!cpu.pipe.WB) {
            cpu.pipe.WB = cpu.pipe.MEM;
            cpu.pipe.MEM.reset();
        }
        // WB will increment completed count
    }
}

// EX 
void stepEX(CPUState &cpu) {
    if (!cpu.pipe.EX) return;

    InFlight &f = *cpu.pipe.EX;
    const Decoded &d = f.d;

    if (f.ex_rem > 0) {
        f.ex_rem--;
        if (f.ex_rem > 0) return;
    }

    // EX just completed
    uint32_t curPC = static_cast<uint32_t>(f.id) * 4;

    // control-flow handling: branch/jump update PC + flush
    if (d.opcode == 0b1100011) { // branches
        if (d.funct3 == 0b100) { // blt
            int32_t v1 = static_cast<int32_t>(cpu.x[d.rs1]);
            int32_t v2 = static_cast<int32_t>(cpu.x[d.rs2]);
            if (v1 < v2) {
                cpu.PC = curPC + d.imm;
                cpu.pipe.IF.reset();
                cpu.pipe.ID.reset();
            }
        }
    } else if (d.opcode == 0b1101111) { // jal (used as 'j')
        uint32_t target = curPC + d.imm;
        cpu.PC = target;
        cpu.pipe.IF.reset();
        cpu.pipe.ID.reset();
    } else if (d.opcode == 0b1100111) { // jalr (used for ret)
        uint32_t target = (cpu.x[d.rs1] + d.imm) & ~1u;
        cpu.PC = target;
        cpu.pipe.IF.reset();
        cpu.pipe.ID.reset();

        if (d.raw == 0x00008067) {
            // canonical ret
            cpu.halted = true;
        }
    }

    // Normal EX promotion
    if (d.is_load || d.is_store) {
        if (!cpu.pipe.MEM) {
            cpu.pipe.MEM = cpu.pipe.EX;
            cpu.pipe.EX.reset();
        }
    }
    else if (d.writes_int || d.writes_fp) {
        if (!cpu.pipe.WB) {
            cpu.pipe.WB = cpu.pipe.EX;
            cpu.pipe.EX.reset();
        }
    }
    else {
        // branch etc that do not write registers
        cpu.pipe.EX.reset();
        cpu.instrCompleted++;
    }
}

// ID/IF/FETCH
void stepFrontEnd(CPUState &cpu) {
    cpu.stalledThisCycle    = false;
    cpu.stallReasonThisCycle.clear();

    if (cpu.done) return;

    bool stall = false;
    string reason;

    // ID -> EX
    if (cpu.pipe.ID) {
        const Decoded &dID = cpu.pipe.ID->d;
        bool srcReady = sourcesReady(dID, cpu.sb);

        if (!srcReady) {
            stall = true;
            reason = "src busy";
            cpu.dataHazardStall++;
        }
        else if (cpu.pipe.EX) {
            stall = true;
            reason = "EX busy";
            cpu.exBusyStall++;
        }
    }

    if (stall) {
        cpu.stallCount++;
        cpu.stalledThisCycle = true;
        cpu.stallReasonThisCycle = reason;
    }

    if (!stall && cpu.pipe.ID) {
        cpu.pipe.EX = cpu.pipe.ID;
        cpu.pipe.ID.reset();
        cpu.pipe.EX->ex_rem = exLatency(cpu.pipe.EX->d);
        setupEX(cpu, *cpu.pipe.EX);
        reserveDest(cpu.pipe.EX->d, cpu.sb);
    }

    // IF -> ID
    if (!stall && cpu.pipe.IF && !cpu.pipe.ID) {
        cpu.pipe.ID = cpu.pipe.IF;
        cpu.pipe.IF.reset();
    }

    // Fetch new instruction
    if (!stall && !cpu.pipe.IF && !cpu.halted) {
        uint32_t index = cpu.PC / 4;
        if (index < cpu.program.size() && cpu.fetched < cpu.maxFetches) {
            InFlight f;
            f.id       = static_cast<int>(index);
            f.d        = cpu.program[index];
            f.ex_rem   = exLatency(f.d);
            f.mem_rem  = memLatency(f.d);
            f.tag      = f.d.type;
            f.mnemonic = f.d.name;
            cpu.pipe.IF = f;

            cpu.PC += 4;              // fall-through PC
            cpu.fetched++;

            if (cpu.fetched >= cpu.maxFetches) {
                cpu.halted = true;
            }
        }
    }
}

// TABLE HELPERS (FIXED)
string padStrict(const string &s, int width) {
    string out = s;
    if ((int)out.size() > width)
        out = out.substr(0, width);
    if ((int)out.size() < width)
        out += string(width - (int)out.size(), ' ');
    return out;
}

string stageStr(const optional<InFlight> &st, bool showLatency, int width) {
    if (!st) return string(width, '.');

    string s = st->d.name;

    if (showLatency) {
        if (st->ex_rem > 0)
            s += " (E" + to_string(st->ex_rem) + ")";
        if (st->mem_rem > 0)
            s += " (M" + to_string(st->mem_rem) + ")";
    }

    return padStrict(s, width);
}

string idStageStr(CPUState &cpu, int width) {
    if (!cpu.pipe.ID) return string(width, '.');

    string s = cpu.pipe.ID->d.name;

    if (cpu.stalledThisCycle) {
        s += " (STALL";
        if (!cpu.stallReasonThisCycle.empty()) {
            s += ":" + cpu.stallReasonThisCycle;
        }
        s += ")";
    }

    return padStrict(s, width);
}

// MAIN
int main() {
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    cout << "=== Dual-CPU RISC-V Pipeline Simulator (with shared MEM bus) ===\n";

    init_RAM();

    CPUState cpu[2];

    // Load CPU0
    {
        ProgramImage img0 = loadProgram("CPU0.txt");
        cpu[0].id = 0;
        cpu[0].program = img0.instrs;
        cpu[0].x[0] = 0;
        cpu[0].x[2] = img0.initialSP;
        cpu[0].x[8] = img0.initialSP;
        cpu[0].PC   = 0;
        cpu[0].fetched = 0;
        cpu[0].maxFetches = cpu[0].program.size() * 255ull;

        cout << "CPU0 program length: " << cpu[0].program.size() << " instructions\n";
    }

    // Load CPU1
    {
        ProgramImage img1 = loadProgram("CPU1.txt");
        cpu[1].id = 1;
        cpu[1].program = img1.instrs;
        cpu[1].x[0] = 0;
        cpu[1].x[2] = img1.initialSP;
        cpu[1].x[8] = img1.initialSP;
        cpu[1].PC   = 0;
        cpu[1].fetched = 0;
        cpu[1].maxFetches = cpu[1].program.size() * 255ull;

        cout << "CPU1 program length: " << cpu[1].program.size() << " instructions\n";
    }

    const int MAX_CYCLES = 500000;
    int cycle = 0;
    int lastGranted = 1; // so CPU0 wins first tie

    const int STAGE_W = 14;
    const int BUS_W   = 40;

    cout << "\nStarting simulation with 255 dynamic passes per CPU (max fetches) and round-robin data-bus arbitration...\n\n";

    // table header
    cout << left
         << setw(6)  << "Cyc"
         << "| " << setw(STAGE_W) << "C0_IF"
         << "| " << setw(STAGE_W) << "C0_ID"
         << "| " << setw(STAGE_W) << "C0_EX"
         << "| " << setw(STAGE_W) << "C0_MEM"
         << "| " << setw(STAGE_W) << "C0_WB"
         << "| " << setw(STAGE_W) << "C1_IF"
         << "| " << setw(STAGE_W) << "C1_ID"
         << "| " << setw(STAGE_W) << "C1_EX"
         << "| " << setw(STAGE_W) << "C1_MEM"
         << "| " << setw(STAGE_W) << "C1_WB"
         << "| " << setw(BUS_W)   << "BUS"
         << "\n";

    cout << string(6 + 2 + (10*STAGE_W) + 2 + BUS_W, '-') << "\n";

    while (!(cpu[0].done && cpu[1].done) && cycle < MAX_CYCLES) {
        ++cycle;

        // WRITEBACK (both CPUs) 
        for (int i = 0; i < 2; ++i) stepWB(cpu[i]);

        // MEM BUS ARBITRATION 
        MemRequest req[2];
        for (int i = 0; i < 2; ++i) {
            if (cpu[i].pipe.MEM) {
                const Decoded &d = cpu[i].pipe.MEM->d;
                if (d.is_load || d.is_store) {
                    req[i].valid   = true;
                    req[i].isLoad  = d.is_load;
                    req[i].isStore = d.is_store;
                    req[i].addr    = cpu[i].pipe.MEM->mem_addr;
                    req[i].cpuId   = i;
                }
            }
        }

        bool grant[2] = {false,false};
        int winner = arbitrateRoundRobin(req[0], req[1], lastGranted);
        if (winner == 0) grant[0] = true;
        else if (winner == 1) grant[1] = true;

        // Prepare BUS info string for this cycle
        string busInfo;
        if (winner == -1) {
            busInfo = "idle";
        } else {
            int cid = winner;
            string op = req[cid].isLoad ? "LD" : "ST";
            string port = memPortFromAddr(req[cid].addr, false);
            busInfo = "CPU" + to_string(cid) + " " + op + " " + port;
            int other = 1 - cid;
            if (req[other].valid) {
                busInfo += " (CPU" + to_string(other) + " wait)";
            }
        }
        if ((int)busInfo.size() < BUS_W)
            busInfo += string(BUS_W - (int)busInfo.size(), ' ');
        else
            busInfo = busInfo.substr(0, BUS_W);

        // MEM STAGE (with grants) 
        for (int i = 0; i < 2; ++i) stepMEM(cpu[i], grant[i]);

        // EX STAGE 
        for (int i = 0; i < 2; ++i) stepEX(cpu[i]);

        // FRONT END (ID/IF/FETCH)
        for (int i = 0; i < 2; ++i) stepFrontEnd(cpu[i]);

        // DONE CHECK
        for (int i = 0; i < 2; ++i) {
            if (!cpu[i].done) {
                bool pipeEmpty = !cpu[i].pipe.IF && !cpu[i].pipe.ID &&
                                 !cpu[i].pipe.EX && !cpu[i].pipe.MEM &&
                                 !cpu[i].pipe.WB;
                bool noMoreFetches =
                    cpu[i].halted ||
                    (cpu[i].PC / 4 >= cpu[i].program.size()) ||
                    (cpu[i].fetched >= cpu[i].maxFetches);

                if (pipeEmpty && noMoreFetches) {
                    cpu[i].done = true;
                    cpu[i].finishCycle = cycle;
                }
            }
        }

        // PRINT TABLE ROW
        cout << setw(6) << cycle << "| "
             << stageStr(cpu[0].pipe.IF,  false, STAGE_W) << "| "
             << idStageStr(cpu[0], STAGE_W)               << "| "
             << stageStr(cpu[0].pipe.EX,  true,  STAGE_W) << "| "
             << stageStr(cpu[0].pipe.MEM, true,  STAGE_W) << "| "
             << stageStr(cpu[0].pipe.WB,  false, STAGE_W) << "| "
             << stageStr(cpu[1].pipe.IF,  false, STAGE_W) << "| "
             << idStageStr(cpu[1], STAGE_W)               << "| "
             << stageStr(cpu[1].pipe.EX,  true,  STAGE_W) << "| "
             << stageStr(cpu[1].pipe.MEM, true,  STAGE_W) << "| "
             << stageStr(cpu[1].pipe.WB,  false, STAGE_W) << "| "
             << busInfo
             << "\n";
    }

    cout << "\nSimulation finished after " << cycle << " cycles.\n\n";

    for (int i = 0; i < 2; ++i) {
        cout << "CPU" << i << " completed " << cpu[i].instrCompleted
             << " dynamic instructions\n";
        if (cpu[i].instrCompleted > 0 && cpu[i].finishCycle > 0) {
            double cpi = double(cpu[i].finishCycle) / double(cpu[i].instrCompleted);
            cout << "CPU" << i << " CPI = " << fixed << setprecision(3) << cpi << "\n";
        } else {
            cout << "CPU" << i << " CPI = (not finished)\n";
        }

        cout << "Final SP (x2) for CPU" << i << " = 0x"
             << hex << setw(8) << setfill('0') << cpu[i].x[2]
             << dec << setfill(' ') << "\n";

        cout << "CPU" << i << " Total Stalls = " << cpu[i].stallCount << "\n";
        cout << "   Data Hazards  = " << cpu[i].dataHazardStall << "\n";
        cout << "   EX Busy       = " << cpu[i].exBusyStall << "\n";
        cout << "   Bus Waits     = " << cpu[i].busWaitStall << "\n\n";
    }

    cout << "Combined Stall Total = "
         << (cpu[0].stallCount + cpu[1].stallCount) << "\n\n";

    // RAM sample from A, B, C
    uint32_t ptrA = read32(ARRAY_A_START);
    uint32_t ptrB = read32(ARRAY_B_START);
    uint32_t ptrC = read32(ARRAY_C_START);

    uint32_t rawA0 = read32(ptrA);
    uint32_t rawB0 = read32(ptrB);
    uint32_t rawC0 = read32(ptrC);

    float a0, b0, c0;
    memcpy(&a0, &rawA0, 4);
    memcpy(&b0, &rawB0, 4);
    memcpy(&c0, &rawC0, 4);

    cout << "RAM Sample (first elements):\n";
    cout << "  A[0] @ 0x" << hex << ptrA << " = "
         << dec << fixed << setprecision(2) << a0 << "\n";
    cout << "  B[0] @ 0x" << hex << ptrB << " = "
         << dec << fixed << setprecision(2) << b0 << "\n";
    cout << "  C[0] @ 0x" << hex << ptrC << " = "
         << dec << fixed << setprecision(2) << c0 << " (sum output region)\n";

    return 0;
}
