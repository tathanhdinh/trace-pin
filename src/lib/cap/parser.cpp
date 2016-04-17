//#include "../../parsing_helper.h"
#include "cap.h"
#include "trace.h"

#include "../type/trace_with_chunk.pb.h"
#include "../tinyformat.h"

#include <fstream>

//static auto protobuf_trace = trace_format::trace_t();
static auto protobuf_chunk = trace_format::chunk_t();
static std::ofstream protobuf_trace_file;
static auto trace_length = uint32_t{0};

static auto real_value_of_reg (const dyn_reg_t& reg_val) -> ADDRINT
{
  auto reg_size = REG_Size(std::get<0>(reg_val));
  ASSERTX((reg_size == 1) || (reg_size == 2) || (reg_size == 4) || (reg_size == 8));

  auto real_val = ADDRINT{0};
  switch (reg_size) {
  case 1:
    real_val = std::get<1>(reg_val).byte[0];
    break;

  case 2:
    real_val = std::get<1>(reg_val).word[0];
    break;

  case 4:
    real_val = std::get<1>(reg_val).dword[0];
    break;

  case 8:
    real_val = std::get<1>(reg_val).qword[0];
    break;
  }

  return real_val;
};

static auto real_value_of_mem (const std::pair<dyn_mem_t, ADDRINT>& mem_val) -> ADDRINT
{
  auto mem_size = std::get<1>(std::get<0>(mem_val));
  ASSERTX((mem_size == 1) || (mem_size == 2) || (mem_size == 4) || (mem_size == 8));

  auto real_val = ADDRINT{0};
  switch (mem_size) {
  case 1:
    real_val = static_cast<uint8_t>(std::get<1>(mem_val));
    break;

  case 2:
    real_val = static_cast<uint16_t>(std::get<1>(mem_val));
    break;

  case 4:
    real_val = static_cast<uint32_t>(std::get<1>(mem_val));
    break;

  case 8:
    real_val = static_cast<uint64_t>(std::get<1>(mem_val));
    break;
  }

  return real_val;
}

auto save_in_simple_format (std::ofstream& output_stream) -> void
{
  tfm::printfln("trace length %d", trace.size());

  std::for_each(trace.begin(), trace.end(), [&output_stream](decltype(trace)::const_reference ins)
  {
    auto ins_addr = std::get<INS_ADDRESS>(ins);
    tfm::format(output_stream, "0x%-12x %-40s", ins_addr,
                cached_ins_at_addr[ins_addr]->disassemble);

    tfm::format(output_stream, "  RR: ");
    for (const auto& reg_val : std::get<INS_READ_REGS>(ins)) {
      tfm::format(output_stream, "[%s:0x%x]", REG_StringShort(std::get<0>(reg_val)), real_value_of_reg(reg_val));
    }

    tfm::format(output_stream, "  RW: ");
    for (const auto& reg_val : std::get<INS_WRITE_REGS>(ins)) {
      tfm::format(output_stream, "[%s:0x%x]", REG_StringShort(std::get<0>(reg_val)), real_value_of_reg(reg_val));
    }

    tfm::format(output_stream, "  MR: ");
    for (const auto & mem_val : std::get<INS_READ_MEMS>(ins)) {
      tfm::format(output_stream, "[0x%x:%d:0x%x]", std::get<0>(std::get<0>(mem_val)), std::get<1>(std::get<0>(mem_val)),
                  real_value_of_mem(mem_val));
    }

    tfm::format(output_stream, "  MW: ");
    for (const auto & mem_val : std::get<INS_WRITE_MEMS>(ins)) {
      tfm::format(output_stream, "[0x%x:%d:0x%x]", std::get<0>(std::get<0>(mem_val)), std::get<1>(std::get<0>(mem_val)),
                  real_value_of_mem(mem_val));
    }

//    if (cached_ins_at_addr[ins_addr]->is_syscall) {
//      auto concret_info = std::get<INS_CONCRETE_INFO>(ins);
//      switch (concret_info.which())
//      {
//      case 0: /* SYS_OPEN */
//      {
//        auto open_concret_info = boost::get<sys_open_info_t>(concret_info);
//        tfm::format(output_stream, " ID: %d[%s:%d]", sys_open_info_t::id,
//                    open_concret_info.path_name, open_concret_info.file_desc);
//        break;
//      }

//      case 1: /* SYS_READ */
//      {
//        auto read_concret_info = boost::get<sys_read_info_t>(concret_info);
//        tfm::format(output_stream, "  ID: %d[0x%x:%d:%d:%c]", sys_read_info_t::id,
//                    read_concret_info.buffer_addr, read_concret_info.buffer_length,
//                    read_concret_info.read_length, read_concret_info.buffer.get()[0]);
//        break;
//      }

//      case 2: /* SYS_WRITE */
//      {
//        auto write_concret_info = boost::get<sys_write_info_t>(concret_info);
//        tfm::format(output_stream, " ID: %d[0x%x:%d:%d:%c]", sys_open_info_t::id,
//                    write_concret_info.buffer_addr, write_concret_info.buffer_length,
//                    write_concret_info.write_length, write_concret_info.buffer.get()[0]);
//        break;
//      }

//      case 3: /* SYS_OTHER */
//      {
//        auto other_concret_info = boost::get<sys_other_info_t>(concret_info);
//        tfm::format(output_stream, " ID: %d", other_concret_info.real_id);
//        break;
//      }
//      }
//    }

    tfm::format(output_stream, "\n");
  });
  return;
}


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

  
  /*auto header_size = trace_header.ByteSize();
  protobuf_trace_file.write(reinterpret_cast<const char*>(&header_size), sizeof(decltype(header_size)));
  protobuf_chunk.SerializeToOstream(&protobuf_trace_file);*/

  trace_header.Clear();
  protobuf_chunk.Clear();

  /*auto trace_segment = std::string();
  trace_header.SerializeToString(&trace_segment);

  trace_header.Clear();

  uint32_t segment_length = trace_segment.length();
  protobuf_trace_file.write(reinterpret_cast<const char*>(&segment_length), sizeof(uint32_t));
  protobuf_trace_file.write(trace_segment.data(), segment_length);*/

  return;
}


//static auto add_trace_module (trace_format::trace_t& trace, const std::string& module_name) noexcept -> void
//{
//  // add a body element
//  auto p_body = trace.add_body();
//  p_body->set_typeid_(trace_format::METADATA);

//  // set this body as metadata
//  p_body->clear_instruction();
//  auto p_metadata = p_body->mutable_metadata();

//  // set the metadata as a module
//  p_metadata->set_typeid_(trace_format::MODULE_TYPE);
//  p_metadata->clear_exception_metadata();
//  p_metadata->clear_wave_metadata();
////  p_metadata->clear_exception();

//  // update info for the module
//  auto p_module = p_metadata->mutable_module_metadata();
//  p_module->set_name(module_name);

//  return;
//}


static auto add_trace_instruction (trace_format::chunk_t& chunk, const dyn_ins_t& ins) -> void
{
  auto ins_address = std::get<INS_ADDRESS>(ins);
  auto p_static_ins = cached_ins_at_addr[ins_address];

//  tfm::printfln("0x%x  %s", ins_address, p_static_ins->disassemble);

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
  p_instruction->set_opcode(/*reinterpret_cast<uint8_t*>(ins_address)*/opc_buffer.get(), p_static_ins->opcode_size);

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
    ASSERTX((mem_type == MEM_READ) || (mem_type == MEM_WRITE));

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

      auto pin_mem_addr_size = std::get<0>(addr_val);
      auto pin_mem_addr      = std::get<0>(pin_mem_addr_size);
      auto pin_mem_size      = std::get<1>(pin_mem_addr_size);
      auto pin_mem_val       = std::get<1>(addr_val);

      static_assert((sizeof(ADDRINT) == 4) || (sizeof(ADDRINT) == 8), "address size not supported");

      switch (sizeof(ADDRINT)) {
      case 4:
        new_mem_addr->set_typeid_(trace_format::BIT32);
        new_mem_addr->set_value_32(pin_mem_addr);
        break;

      case 8:
        new_mem_addr->set_typeid_(trace_format::BIT64);
        new_mem_addr->set_value_64(pin_mem_addr);
        break;
      }

      assert((pin_mem_size == 1) || (pin_mem_size == 2) || (pin_mem_size == 4) || (pin_mem_size == 8));

      switch (pin_mem_size) {
      case 1:
        new_mem_val->set_typeid_(trace_format::BIT8);
        new_mem_val->set_value_8(pin_mem_val);
        break;

      case 2:
        new_mem_val->set_typeid_(trace_format::BIT16);
        new_mem_val->set_value_16(pin_mem_val);
        break;

      case 4:
        new_mem_val->set_typeid_(trace_format::BIT32);
        new_mem_val->set_value_32(pin_mem_val);
        break;

      case 8:
        new_mem_val->set_typeid_(trace_format::BIT64);
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
//  if (p_static_ins->is_special) {
//    auto concrete_info = p_instruction->add_concrete_info();
//    concrete_info->set_typeid_(trace_format::NOT_RETRIEVED);
//  }
//  else {
    // set read/write registers
    add_registers(REG_READ);
    add_registers(REG_WRITE);

    // set read/write memories
    add_mems(MEM_READ);
    add_mems(MEM_WRITE);
//  }
#endif

  return;
}


//auto convert_trace_to_byte_segments (trace_format::trace_t& captured_trace, uint32_t segment_size) -> std::string
//{
//  auto trace_string = std::string("");
//  return trace_string;
//}


auto flush_trace_in_protobuf_format () -> void
{
  if (!trace.empty()) {
    tfm::format(std::cerr, "flush %d instructions\n", trace.size());
//    tfm::printfln("flush %d instructions", trace.size());

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

    /*auto chunk_size = protobuf_chunk.ByteSize();
    protobuf_trace_file.write(reinterpret_cast<const char*>(&chunk_size), sizeof(decltype(chunk_size)));
    protobuf_chunk.SerializeToOstream(&protobuf_trace_file);*/

    trace.clear();
    protobuf_chunk.Clear();

    /*auto trace_segment = std::string();
    protobuf_chunk.SerializePartialToString(&trace_segment);

    trace.clear();
    protobuf_chunk.Clear();

    uint32_t segment_length = trace_segment.length();
    protobuf_trace_file.write(reinterpret_cast<const char*>(&segment_length), sizeof(uint32_t));
    protobuf_trace_file.write(trace_segment.data(), segment_length);*/
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

//auto cap_save_trace_to_file (const std::string& filename, bool proto_or_simple) noexcept -> void
//{
//  std::ofstream trace_file(filename.c_str(),
//                           std::ofstream::out | std::ofstream::binary | std::ofstream::trunc);

//  if (trace_file.is_open()) {
//    if (proto_or_simple) save_in_protobuf_format(trace_file);
//    else save_in_simple_format(trace_file);

//    trace_file.close();
//  }
//  else {
//    tfm::printfln("cannot save to file %", filename);
//  }

//  return;
//}


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
