#ifndef TRACE_H
#define TRACE_H

#include "instruction.h"

#include <cstdlib>
#include <algorithm>
#include <tuple>
#include <list>

#include <boost/variant.hpp>

//using dynamic_register_t  = std::pair<REG, PIN_REGISTER>;
//using dyn_mem_t  = std::pair<ADDRINT, UINT8>;

using dynamic_registers_t = std::map<REG, PIN_REGISTER>;
using dynamic_memories_t = std::map<ADDRINT, UINT8>;

using dyn_instruction_t = std::tuple<ADDRINT,             // address of instruction
                                     THREADID,            // id of containing thread
                                     dynamic_registers_t, // read registers
                                     dynamic_registers_t, // write registers
                                     dynamic_memories_t,  // read memory addresses
                                     dynamic_memories_t   // write memory addresses
                                     >;

// list is prefered since new instructions will be added regularly
using dynamic_instructions_t = std::list<dyn_instruction_t>;

extern dynamic_instructions_t    trace;
extern address_instruction_map_t cached_instruction_at_address;

enum
  {
    INS_ADDRESS    = 0,
    INS_THREAD_ID  = 1,
    INS_READ_REGS  = 2,
    INS_WRITE_REGS = 3,
    INS_LOAD_MEMS  = 4,
    INS_STORE_MEMS = 5,
  };

#endif // TRACE_H
