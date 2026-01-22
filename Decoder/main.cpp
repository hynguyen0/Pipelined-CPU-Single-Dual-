#include <iostream>
#include <string>
#include <bitset>
#include <iomanip>
using namespace std;

// Structure that stores all of the control signals.
// Each field is initialized to 0 by default.
struct Control {
    int Branch;     // used for branch instructions (BEQ, BNE)
    int MemRead;    // enables reading from memory (LW)
    int MemToReg;   // selects between memory data and ALU result
    int ALUop;      // tells ALU control what operation type to do
    int MemWrite;   // enables writing to memory (SW)
    int RegWrite;   // enables writing back to register file
    int ALUSrc;     // selects between register or immediate for ALU input
    int Jump;       // used for jump instructions (JAL, JALR)
};

// Function that returns a string based on the opcode.
// This helps us easily tell what type of instruction it is.
string getType(unsigned int opcode) {
    if (opcode == 0b0110011) return "R-type";         // add, sub, and, or, etc.
    if (opcode == 0b0010011) return "I-type";         // addi, andi, ori
    if (opcode == 0b0000011) return "Load";           // lw, lb
    if (opcode == 0b0100011) return "Store";          // sw, sb
    if (opcode == 0b1100011) return "Branch";         // beq, bne
    if (opcode == 0b1101111) return "JAL";            // jump
    if (opcode == 0b0110111) return "LUI";            // load upper immediate
    if (opcode == 0b0010111) return "AUIPC";          // add upper imm to PC
    if (opcode == 0b1110011) return "CSR";            // control/status register
    return "Unknown";                                 // anything else
}

// Function that sets control signal values depending on opcode.
// These correspond to what happens in hardware.
Control setCtrl(unsigned int opcode) {
    Control c = {0,0,0,0,0,0,0,0}; // initialize all signals to 0

    // The control logic below is simplified based on the RISC-V table.
    if (opcode == 0b0110011) { 
        // R-type: arithmetic (ADD, SUB, etc.)
        c.ALUop = 10;
        c.RegWrite = 1;
    } 
    else if (opcode == 0b0010011) { 
        // I-type: immediate arithmetic (ADDI, ANDI, ORI)
        c.ALUop = 00;
        c.RegWrite = 1;
        c.ALUSrc = 1;
    } 
    else if (opcode == 0b0000011) { 
        // LOAD instructions (LW, LB)
        c.ALUop = 00;
        c.RegWrite = 1;
        c.MemRead = 1;
        c.MemToReg = 1;
        c.ALUSrc = 1;
    } 
    else if (opcode == 0b0100011) { 
        // STORE instructions (SW, SB)
        c.ALUop = 00;
        c.MemWrite = 1;
        c.ALUSrc = 1;
    } 
    else if (opcode == 0b1100011) { 
        // BRANCH instructions (BEQ, BNE)
        c.ALUop = 01;
        c.Branch = 1;
    } 
    else if (opcode == 0b1101111) { 
        // JUMP (JAL)
        c.ALUop = 10;
        c.RegWrite = 1;
        c.Jump = 1;
    } 
    else if (opcode == 0b0110111) { 
        // LUI (load upper immediate)
        c.ALUop = 10;
        c.RegWrite = 1;
        c.ALUSrc = 1;
    }
    return c;
}

int main() {
    // User enters a 32-bit instruction as a string of 0s and 1s
    string instr;
    cout << "Enter 32-bit instruction (binary): ";
    cin >> instr;

    // Check if the user typed exactly 32 bits
    if (instr.size() != 32) {
        cout << "Error: Instruction must be 32 bits long.\n";
        return 0;
    }

    // Extract each field from the binary string using substr().
    // substr(start, length) picks out specific bits.
    unsigned int opcode = stoi(instr.substr(25,7),nullptr,2); // bits [6:0]
    unsigned int rd     = stoi(instr.substr(20,5),nullptr,2); // bits [11:7]
    unsigned int funct3 = stoi(instr.substr(17,3),nullptr,2); // bits [14:12]
    unsigned int rs1    = stoi(instr.substr(12,5),nullptr,2); // bits [19:15]
    unsigned int rs2    = stoi(instr.substr(7,5),nullptr,2);  // bits [24:20]
    unsigned int funct7 = stoi(instr.substr(0,7),nullptr,2);  // bits [31:25]

    // Display the instruction fields for the user.
    cout << "\n--- Instruction Breakdown ---\n";
    cout << "Opcode : " << bitset<7>(opcode) << " (" << opcode << ")\n";
    cout << "rd     : x" << rd << endl;
    cout << "rs1    : x" << rs1 << endl;
    cout << "rs2    : x" << rs2 << endl;
    cout << "funct3 : " << bitset<3>(funct3) << endl;
    cout << "funct7 : " << bitset<7>(funct7) << endl;
    cout << "Format : " << getType(opcode) << endl;

    // If the instruction is I-type or Load, print immediate field.
    // Immediate values come from bits [31:20].
    if (opcode == 0b0010011 || opcode == 0b0000011) {
        string imm_str = instr.substr(0,12); // top 12 bits
        int imm = stoi(imm_str, nullptr, 2);
        cout << "Immediate (binary): " << imm_str << " (" << imm << ")\n";
    }

    // Generate control signals using the function defined above.
    Control c = setCtrl(opcode);

    // Output the control signals in a formatted way using setw().
    // This makes it easier to line up the values like a table.
    cout << "\n--- Control Signals ---\n";
    cout << left
         << setw(12) << "Branch:"   << c.Branch   << endl
         << setw(12) << "MemRead:"  << c.MemRead  << endl
         << setw(12) << "MemToReg:" << c.MemToReg << endl
         << setw(12) << "ALUop:"    << c.ALUop    << endl
         << setw(12) << "MemWrite:" << c.MemWrite << endl
         << setw(12) << "RegWrite:" << c.RegWrite << endl
         << setw(12) << "ALUSrc:"   << c.ALUSrc   << endl
         << setw(12) << "Jump:"     << c.Jump     << endl;

    cout << "\nProgram finished.\n";
    return 0;
}