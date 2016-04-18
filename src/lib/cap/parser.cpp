//#include "../../parsing_helper.h"
#include "cap.h"
#include "trace.h"

#include "../type/trace_with_chunk.pb.h"
#include "../tinyformat.h"

#include <fstream>

static auto protobuf_chunk = trace_format::chunk_t();
static std::ofstream protobuf_trace_file;
static auto trace_length = uint32_t{0};

//static auto real_value_of_reg (const dyn_reg_t& reg_val) -> ADDRINT
//{
//  auto reg_size = REG_Size(std::get<0>(reg_val));
//  ASSERTX((reg_size == 1) || (reg_size == 2) || (reg_size == 4) || (reg_size == 8));

//  auto real_val = ADDRINT{0};
//  switch (reg_size) {
//  case 1:
//    real_val = std::get<1>(reg_val).byte[0];
//    break;

//  case 2:
//    real_val = std::get<1>(reg_val).word[0];
//    break;

//  case 4:
//    real_val = std::get<1>(reg_val).dword[0];
//    break;

//  case 8:
//    real_val = std::get<1>(reg_val).qword[0];
//    break;
//  }

//  return real_val;
//};


static auto set_trace_header () -> void
{
  auto trace_header = trace_format::header_t();

  static_assert((sizeof(ADDRINT) == 4) || (sizeof(ADDRINT) == 8), "address size not supported");

  switch (sizeof(ADDRINT)) {
  case 4:
    trace_header.set_architecture(trace_format::X86);
    trace_header.set_address_size(trace_format::BIT32);
    break;

  case 8:
    trace_header.set_architecture(trace_format::X86_64);
    trace_header.set_address_size(trace_format::BIT64);
    break;
  }


  auto header_size = trace_header.ByteSize();
  auto header_buffer = std::shared_ptr<char>(new char[header_size], std::default_delete<char[]>());

  trace_header.SerializeToArray(header_buffer.get(), header_size);

  // save the length of the header and then the buffer containing header
  protobuf_trace_file.write(reinterpret_cast<const char*>(&header_size), sizeof(decltype(header_size)));
  protobuf_trace_file.write(header_buffer.get(), header_size);

  trace_header.Clear();
  protobuf_chunk.Clear();

  return;
}


static auto add_trace_instruction (trace_format::chunk_t& chunk, const dyn_ins_t& ins) -> void
{
  auto ins_address = std::get<INS_ADDRESS>(ins);
  auto p_static_ins = cached_ins_at_addr[ins_address];

  // add a new body as an instruction
  auto p_ins_body = chunk.add_body();
  p_ins_body->set_typeid_(trace_format::INSTRUCTION);
  p_ins_body->clear_metadata();

  // create an instruction for this body, and set some information
  auto p_instruction = p_ins_body->mutable_instruction();
  p_instruction->set_thread_id(std::get<INS_THREAD_ID>(ins));

  auto opc_size = p_static_ins->opcode_size;
  auto opc_buffer = std::shared_ptr<uint8_t>(new uint8_t[opc_size], std::default_delete<uint8_t[]>());

  PIN_SafeCopy(opc_buffer.get(), reinterpret_cast<const VOID*>(ins_address), opc_size);
  p_instruction->set_opcode(opc_buffer.get(), p_static_ins->opcode_size);

  auto p_ins_addr = p_instruction->mutable_address();

  static_assert(((sizeof(ADDRINT) == 4) || (sizeof(ADDRINT) == 8)), "address size must be 32 or 64 bit");

  switch (sizeof(ADDRINT)) {
  case 4:
    p_ins_addr->set_typeid_(trace_format::BIT32);
    p_ins_addr->set_value_32(ins_address);
    p_ins_addr->clear_value_64();
    break;

  case 8:
    p_ins_addr->set_typeid_(trace_format::BIT64);
    p_ins_addr->set_value_64(ins_address);
    p_ins_addr->clear_value_32();
    break;
  }

  p_instruction->set_disassemble(p_static_ins->disassemble);

  enum REG_T { REG_READ = 0, REG_WRITE = 1 };
  auto add_registers = [&p_instruction, &ins, &p_static_ins](REG_T reg_type) -> void
  {
    const auto & regs = (reg_type == REG_READ) ? p_static_ins->src_registers : p_static_ins->dst_registers;
    auto value_of_reg = (reg_type == REG_READ) ? std::get<INS_READ_REGS>(ins) : std::get<INS_WRITE_REGS>(ins);
    auto reg_typeid = (reg_type == REG_READ) ? trace_format::REGREAD : trace_format::REGWRITE;

    std::for_each(std::begin(regs), std::end(regs), [&](REG pin_reg)
    {
      // create a new concrete info
      auto p_new_con_info = p_instruction->add_concrete_info();

      // set corresponding type for the concrete info (REGLOAD or REGSTORE)
      p_new_con_info->set_typeid_(reg_typeid);

      // allocate a new register for the concrete info, set its name
      auto p_new_reg =
          (reg_type == REG_READ) ? p_new_con_info->mutable_read_register() : p_new_con_info->mutable_write_register();
      p_new_reg->set_name(REG_StringShort(pin_reg));

      // then set its value
      auto p_reg_value = p_new_reg->mutable_value();
      switch (REG_Width(pin_reg)) { // or we can use REG_Size
      case REGWIDTH_8:
        p_reg_value->set_typeid_(trace_format::BIT8);
        p_reg_value->set_value_8(value_of_reg[pin_reg].byte[0]);
        break;

      case REGWIDTH_16:
        p_reg_value->set_typeid_(trace_format::BIT16);
        p_reg_value->set_value_16(value_of_reg[pin_reg].word[0]);
        break;

      case REGWIDTH_32:
        p_reg_value->set_typeid_(trace_format::BIT32);
        p_reg_value->set_value_32(value_of_reg[pin_reg].dword[0]);
        break;

      case REGWIDTH_64:
        p_reg_value->set_typeid_(trace_format::BIT64);
        p_reg_value->set_value_64(value_of_reg[pin_reg].qword[0]);
        break;

      default:
        break;
      }
    });


    return;
  };

  enum MEM_T { MEM_READ = 0, MEM_WRITE = 1 };
  auto add_mems = [&p_instruction, &ins](MEM_T mem_type) -> void
  {
    auto mems = (mem_type == MEM_READ) ? std::get<INS_READ_MEMS>(ins) : std::get<INS_WRITE_MEMS>(ins);

    for (auto const& addr_val : mems) {

      // add a new concrete info and set it by the memory instance
      auto new_mem_con_info = p_instruction->add_concrete_info();
      switch (mem_type) {
      case MEM_READ:
        new_mem_con_info->set_typeid_(trace_format::MEMLOAD);
        break;

      case MEM_WRITE:
        new_mem_con_info->set_typeid_(trace_format::MEMSTORE);
        break;
      }

      // add a new memory instance
      auto new_mem = (mem_type == MEM_READ) ?
            new_mem_con_info->mutable_load_memory() : new_mem_con_info->mutable_store_memory();
      auto new_mem_addr = new_mem->mutable_address();
      auto new_mem_val = new_mem->mutable_value();

      auto pin_mem_addr = std::get<0>(addr_val);
      auto pin_mem_val = std::get<1>(addr_val);


      switch (sizeof(ADDRINT)) {
      case 4:
        new_mem_addr->set_typeid_(trace_format::BIT32);
        new_mem_val->set_typeid_(trace_format::BIT32);

        new_mem_addr->set_value_32(pin_mem_addr);
        new_mem_val->set_value_32(pin_mem_val);
        break;

      case 8:
        new_mem_addr->set_typeid_(trace_format::BIT64);
        new_mem_val->set_typeid_(trace_format::BIT64);

        new_mem_addr->set_value_64(pin_mem_addr);
        new_mem_val->set_value_64(pin_mem_val);
        break;
      }
    }
    return;
  };

#if defined(FAST_TRACING)
  auto concrete_info = p_instruction->add_concrete_info();
  concrete_info->set_typeid_(trace_format::NOT_RETRIEVED);
#else

  // set read/write registers
  add_registers(REG_READ);
  add_registers(REG_WRITE);

  // set read/write memories
  add_mems(MEM_READ);
  add_mems(MEM_WRITE);
#endif

  return;
}


auto flush_trace_in_protobuf_format () -> void
{
  if (!trace.empty()) {
    tfm::format(std::cerr, "flush %d instructions\n", trace.size());

    trace_length += trace.size();

    // add instructions
    for (const auto& ins : trace) {
      add_trace_instruction(protobuf_chunk, ins);
    }

    auto chunk_size = protobuf_chunk.ByteSize();
    auto chunk_buffer = std::shared_ptr<char>(new char[chunk_size], std::default_delete<char[]>());

    protobuf_chunk.SerializeToArray(chunk_buffer.get(), chunk_size);

    protobuf_trace_file.write(reinterpret_cast<const char*>(&chunk_size), sizeof(decltype(chunk_size)));
    protobuf_trace_file.write(chunk_buffer.get(), chunk_size);

    trace.clear();
    protobuf_chunk.Clear();
  }

  return;
}


/*====================================================================================================================*/
/*                                                     exported functions                                             */
/*====================================================================================================================*/

auto cap_parser_initialize (const std::string& filename) -> void
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

auto cap_flush_trace () -> void
{
  flush_trace_in_protobuf_format();
  return;
}

auto cap_parser_finalize () -> void
{
  try {
    tfm::format(std::cerr, "trace length: %d instructions\n", trace_length);
    protobuf_trace_file.close();

    // free internal objects of protobuf
    google::protobuf::ShutdownProtobufLibrary();
  }
  catch (const std::exception& expt) {
    tfm::printfln("%s", expt.what());
    PIN_ExitProcess(1);
  }
}


auto cap_load_trace_from_file (std::string& filename) -> void
{
  std::ifstream trace_file(filename.c_str(), std::ifstream::in | std::ifstream::binary);

  auto trace_loader = trace_format::trace_t();
  if (trace_loader.ParseFromIstream(&trace_file)) {
    auto trace_header = trace_loader.header();
  }

  trace_file.close();
  google::protobuf::ShutdownProtobufLibrary();
  return;
}
