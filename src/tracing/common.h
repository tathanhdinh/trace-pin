#ifndef TRACE_H
#define TRACE_H

#include "instruction.h"

#include <cstdlib>
#include <algorithm>
#include <tuple>
#include <list>

#include <boost/variant.hpp>

using dyn_reg_t  = std::pair<REG, PIN_REGISTER>;
//using dyn_mem_t  = std::pair<ADDRINT, UINT8>;

using dyn_regs_t = std::map<REG, PIN_REGISTER>;
using dyn_mems_t = std::map<ADDRINT, ADDRINT>;

using dyn_ins_t = std::tuple<
  ADDRINT,        // address of instruction
  THREADID,       // id of containing thread
  dyn_regs_t,     // read registers
  dyn_regs_t,     // write registers
  dyn_mems_t,     // read memory addresses
  dyn_mems_t      // write memory addresses
  >;

// list is prefered since new instructions will be added regularly
using dyn_inss_t = std::list<dyn_ins_t>;

extern dyn_inss_t                trace;
extern map_address_instruction_t cached_ins_at_addr;

enum
  {
    INS_ADDRESS       = 0,
    INS_THREAD_ID     = 1,
    INS_READ_REGS     = 2,
    INS_WRITE_REGS    = 3,
    INS_READ_MEMS     = 4,
    INS_WRITE_MEMS    = 5,
  };

//auto normalize_hex_string (const std::string& input) -> std::string;

#endif // TRACE_H
