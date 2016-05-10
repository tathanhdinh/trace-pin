
#ifndef INSTRUCTION_H
#define INSTRUCTION_H

#include <pin.H>
extern "C" {
#include "xed-interface.h"
}

#include <string>
#include <memory>
#include <vector>
#include <map>

class instruction
{
 public:
  ADDRINT     address;
  ADDRINT     next_address;
//  std::string opcode;
//  xed_decoded_inst_t* decoded_opcode;
  uint8_t opcode_size;
  std::shared_ptr<uint8_t> opcode_buffer;

  std::string disassemble;

  std::string including_image;
  std::string including_routine_name;

  bool has_fall_through;

  bool is_call;
  bool is_branch;
  bool is_syscall;
//  bool is_sysret;
  bool is_ret;
  bool is_special;

  xed_category_enum_t category;
  xed_iclass_enum_t iclass;

  std::vector<REG> src_registers;
  std::vector<REG> dst_registers;

  bool is_memory_read;
  bool is_memory_read2;
  bool is_memory_write;

 public:
  instruction(const INS& ins);
};

using p_instruction_t             = std::shared_ptr<instruction>;
using p_instructions_t            = std::vector<p_instruction_t>;
using address_instruction_map_t   = std::map<ADDRINT, p_instruction_t>;
using p_address_instruction_map_t = std::shared_ptr<address_instruction_map_t>;

#endif
















