This project aims to design a Pipelined CPU in C++. The code simulates RAM, decodes assembly text files, then pushes instructions in simulated cycles.
The decoder for the CPU reads instructions from the assemble code and gets the op code from it.
Each opcode has a specific instruction (addi, flw, lw, fadd.s, ...) The CPU takes each instruction and performs the specifed task.
If a load or store insturction is met, the CPU uses the simulated RAM to populate a specified memory array.
