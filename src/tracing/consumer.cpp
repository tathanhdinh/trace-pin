#include "export.h"
#include "common.h"

#include "trace_with_chunk.pb.h"
#include "tinyformat.h"

#include <fstream>

static auto protobuf_chunk = trace_format::chunk_t();
static std::ofstream protobuf_trace_file;
static auto current_trace_length = uint32_t{0};

static auto set_trace_header () -> void
{
  auto trace_header = trace_format::header_t();

  static_assert((sizeof(ADDRINT) == 4) || (sizeof(ADDRINT) == 8), "address size not supported");

  switch (sizeof(ADDRINT)) {
  case 4:
    trace_header.set_architecture(trace_format::X86);
    break;

  case 8:
    trace_header.set_architecture(trace_format::X86_64);
    break;
  }

  // get header size and declare a buffer to serialize
  auto header_size = trace_header.ByteSize();
  auto header_buffer = std::shared_ptr<char>(new char[header_size], std::default_delete<char[]>());

  // serialize header to the buffer
  trace_header.SerializeToArray(header_buffer.get(), header_size);

  // save the length of the header and the buffer
  protobuf_trace_file.write(reinterpret_cast<const char*>(&header_size), sizeof(decltype(header_size)));
  protobuf_trace_file.write(header_buffer.get(), header_size);

  trace_header.Clear();
  protobuf_chunk.Clear();

  return;
}


enum REG_RW_T { REG_READ = 0, REG_WRITE = 1 };
auto add_registers_into_protobuf_instruction(const dyn_instruction_t& ins, const p_instruction_t static_ins,
                                             trace_format::instruction_t* p_proto_ins, REG_RW_T reg_type) -> void
{
  const auto& regs = (reg_type == REG_READ) ? static_ins->src_registers : static_ins->dst_registers;
  const auto& reg_value_map = (reg_type == REG_READ) ? std::get<INS_READ_REGS>(ins) : std::get<INS_WRITE_REGS>(ins);

  for (const auto& pin_reg : regs) {
    auto p_new_concrete_info = p_proto_ins->add_c_info();
    auto p_reg_info = (reg_type == REG_READ) ? p_new_concrete_info->mutable_read_register() : p_new_concrete_info->mutable_write_register();

    p_reg_info->set_name(REG_StringShort(pin_reg));
    switch (sizeof(ADDRINT)) {
    case 4:
      (p_reg_info->mutable_value())->set_value_32(reg_value_map.at(pin_reg).dword[0]);
      break;

    case 8:
      (p_reg_info->mutable_value())->set_value_64(reg_value_map.at(pin_reg).qword[0]);
      break;
    }
  }

  return;
}


enum MEM_RW_T { MEM_LOAD = 0, MEM_STORE = 1 };
auto add_memories_into_protobuf_instruction (const dyn_instruction_t& ins,
                                             trace_format::instruction_t* p_proto_ins, MEM_RW_T mem_type) -> void
{
  const auto& mems = (mem_type == MEM_LOAD) ? std::get<INS_LOAD_MEMS>(ins) : std::get<INS_STORE_MEMS>(ins);

  for (const auto& addr_val : mems) {
    auto p_new_concrete_info = p_proto_ins->add_c_info();
    auto p_mem_info = (mem_type == MEM_LOAD) ? p_new_concrete_info->mutable_load_memory() : p_new_concrete_info->mutable_store_memory();

    p_mem_info->set_value(std::get<1>(addr_val));
    switch (sizeof(ADDRINT)) {
    case 4:
      (p_mem_info->mutable_address())->set_value_32(std::get<0>(addr_val));
      break;
    case 8:
      (p_mem_info->mutable_address())->set_value_64(std::get<0>(addr_val));
      break;
    }
  }

  return;
}

static auto add_instruction_into_chunk (trace_format::chunk_t& chunk, const dyn_instruction_t& ins) -> void
{
  auto ins_address = std::get<INS_ADDRESS>(ins);
  const auto p_static_ins = cached_instruction_at_address[ins_address];

  // add new instruction
  auto p_new_ins = chunk.add_instructions();

  // fill thread_id
  p_new_ins->set_thread_id(std::get<INS_THREAD_ID>(ins));

  // fill address
  auto p_ins_addr = p_new_ins->mutable_address();
  switch (sizeof(ADDRINT)) {
  case 4:
    p_ins_addr->set_value_32(ins_address);
    break;

  case 8:
    p_ins_addr->set_value_64(ins_address);
    break;
  }

  // fill opcode
  p_new_ins->set_opcode(p_static_ins->opcode_buffer.get(), p_static_ins->opcode_size);

  // fill disassemble
  p_new_ins->set_disassemble(p_static_ins->disassemble);

  // fill read/write registers
  add_registers_into_protobuf_instruction(ins, p_static_ins, p_new_ins, REG_READ);
  add_registers_into_protobuf_instruction(ins, p_static_ins, p_new_ins, REG_WRITE);

  // fill load/store memories
  add_memories_into_protobuf_instruction(ins, p_new_ins, MEM_LOAD);
  add_memories_into_protobuf_instruction(ins, p_new_ins, MEM_STORE);

  return;
}


/*====================================================================================================================*/
/*                                                     exported functions                                             */
/*====================================================================================================================*/

auto pintool_initialize_trace_file (const std::string& filename) -> void
{
  try {
    protobuf_trace_file.open(filename.c_str(), std::ofstream::out | std::ofstream::binary | std::ofstream::trunc);
    set_trace_header();
  }
  catch (const std::exception& expt) {
    tfm::printfln("%s", expt.what());
    PIN_ExitProcess(1);
  }
}

auto pintool_flush_trace () -> void
{
  try {
    if (!trace.empty()) {
      tfm::format(std::cerr, "flush %d instructions\n", trace.size());

      // add instructions
      for (auto& ins : trace) {
        add_instruction_into_chunk(protobuf_chunk, ins);
      }

      current_trace_length += trace.size();

      auto chunk_size = protobuf_chunk.ByteSize();
      auto chunk_buffer = std::shared_ptr<char>(new char[chunk_size], std::default_delete<char[]>());

      protobuf_chunk.SerializeToArray(chunk_buffer.get(), chunk_size);

      protobuf_trace_file.write(reinterpret_cast<const char*>(&chunk_size), sizeof(decltype(chunk_size)));
      protobuf_trace_file.write(chunk_buffer.get(), chunk_size);

      trace.clear();
      protobuf_chunk.Clear();
    }
  }
  catch (const std::exception& expt) {
    tfm::printfln("exeception: %s", expt.what());
    PIN_ExitProcess(1);
  }

  return;
}

auto pintool_finalize_output_file () -> void
{
  try {
    tfm::format(std::cerr, "trace length: %d instructions\n", current_trace_length);
    protobuf_trace_file.close();

    // free internal objects of protobuf
    google::protobuf::ShutdownProtobufLibrary();
  }
  catch (const std::exception& expt) {
    tfm::printfln("%s", expt.what());
    PIN_ExitProcess(1);
  }
}
