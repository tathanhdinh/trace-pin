#include <pin.H>

#include "tracing/tinyformat.h"
#include "tracing/instruction.h"
#include "tracing/export.h"

#include "json.hpp"

#include <fstream>
#include <boost/algorithm/string.hpp>
#include <boost/filesystem.hpp>

#include <regex>

#include <algorithm>
#include <exception>
#include <type_traits>

#define PIN_INIT_FAILED 1
#define UNUSED_DATA 0

/*====================================================================================================================*/
/*                                                command line handling functions                                     */
/*====================================================================================================================*/


static KNOB<uint32_t> trace_length_knob          (KNOB_MODE_WRITEONCE, "pintool", "length", "10000", "length of trace");

static KNOB<ADDRINT> skip_full_address_knob      (KNOB_MODE_APPEND, "pintool", "skip-full", "0x0", "skipping call address");

static KNOB<ADDRINT> skip_auto_address_knob      (KNOB_MODE_APPEND, "pintool", "skip-auto", "0x0", "skipping called address");

static KNOB<UINT32> loop_count_knob              (KNOB_MODE_WRITEONCE, "pintool", "loop-count", "1", "loop count");

static KNOB<string> config_file                  (KNOB_MODE_WRITEONCE, "pintool", "conf", "", "configuration file, for parameterized analysis");

static KNOB<string> output_file                  (KNOB_MODE_WRITEONCE, "pintool", "out", "", "output file, for resulted trace");


/*====================================================================================================================*/
/*                                                     support functions                                              */
/*====================================================================================================================*/

auto get_pin_register_from_name (const std::string& reg_name) -> REG
{
  auto upper_reg_name = std::string(reg_name);
  std::transform(std::begin(upper_reg_name), std::end(upper_reg_name), std::begin(upper_reg_name),
                 [](unsigned char c) { return std::toupper(c); });

  std::underlying_type<REG>::type reg_id;
  for (reg_id = REG_INVALID_ ; reg_id < REG_LAST; ++reg_id) {
    auto pin_reg_name = REG_StringShort(static_cast<REG>(reg_id));
    if (pin_reg_name == upper_reg_name) break;
  }

  return static_cast<REG>(reg_id);
}

auto parse_configuration (const std::string& filename) -> void
{
  std::ifstream config_file(filename.c_str(), std::ifstream::in);
  if (!config_file.is_open()) throw std::logic_error("cannot open configuration file");

  nlohmann::json config_json; config_file >> config_json;

  // parse "start/stop" addresses
  std::string start_address_str = config_json["start"];
  auto start_address = static_cast<ADDRINT>(std::stoul(start_address_str, 0, 0));

  std::string stop_address_str = config_json["stop"];
  auto stop_address = static_cast<ADDRINT>(std::stoul(stop_address_str, 0, 0));

  pintool_set_start_address(start_address);
  pintool_set_stop_address(stop_address);

  // parse "skip" entries
  auto skip_entries = std::vector<nlohmann::json>{config_json["skip"]};
  for (const auto& skip_elem : skip_entries) {
    std::string skip_type = skip_elem["type"];

    auto skip_address = ADDRINT{skip_elem["address"]};

    if (skip_type == "caller") pintool_add_caller_skip_address(skip_address);
    else if (skip_type == "callee") pintool_add_callee_skip_addresses(skip_address);
    else throw std::logic_error("type of skip must be either \"caller\" or \"callee\"");
  }

  // parse "modify" entries
  auto modify_entries = std::vector<nlohmann::json>{config_json["modify"]};
  for (const auto& modify_elem : modify_entries) {
    std::string location_address_str = modify_elem["location"]["address"];
    auto location_address = static_cast<ADDRINT>(std::stoul(location_address_str, 0, 0));

    std::string location_position_str = modify_elem["location"]["position"];
    auto location_position = bool{false};
    if (location_position_str == "before") location_position = false;
    else if (location_position_str == "after") location_position = true;
    else throw std::logic_error("position of modification must be either \"before\" or \"after\"");

    nlohmann::json target_entries = modify_elem["targets"];
    for (const auto& target_elem : target_entries) {
      std::string target_type_str = target_elem["type"];
      if (target_type_str == "register") {
        std::string target_register_str = target_elem["name"];
        auto pin_reg = get_pin_register_from_name(target_register_str);

        std::string target_value_str = target_elem["value"];
        auto target_value = static_cast<ADDRINT>(std::stoul(target_value_str, 0, 0));
      }
    }
  }

  return;
}


auto load_configuration_from_file (const std::string& filename) -> void
{
  std::ifstream config_file(filename.c_str(), std::ifstream::in);
  auto line = std::string();
  while (std::getline(config_file, line)) {

    line = boost::trim_copy(line);

    if (line.front() != '#') {

      auto fields = std::vector<std::string>();
      boost::split(fields, line, boost::is_any_of(","), boost::token_compress_on);
      ASSERTX(fields.size() >= 5);

      auto unconverted_idx = std::size_t{0};

      /*
       * each entry in the configuration file has one of the following form:
       *  (1) ins_addr, exec_order, mem_addr:mem_size, mem_value, patch_point, optional_fields
       *  (2) ins_addr, exec_order, [reg_name]:mem_size, mem_value, patch_point, optional_fields
       *  (3) ins_addr, exec_order, reg_name:low_bit_pos:high_bit_pos, reg_value, patch_point, optional_fields
       */

      auto ins_addr = static_cast<ADDRINT>(std::stoul(fields[0], &unconverted_idx, 16));      // address of the instruction: field 0
      auto exec_order = static_cast<UINT32>(std::stoul(fields[1]));                           // execution order: field 1
      auto patched_value = static_cast<ADDRINT>(std::stoul(fields[3], &unconverted_idx, 16)); // patched value: field 3
      auto patch_point = (fields[4] == "1");                                                  // patching point (false = before, true = after): field 4

      if (std::count(fields[2].begin(), fields[2].end(), ':') == 1) { // (1) or (2)
        auto location_and_size_strs = std::vector<std::string>{};
        boost::split(location_and_size_strs, fields[2], boost::is_any_of(":"), boost::token_compress_on);

        auto patch_location_str = location_and_size_strs[0]; auto patch_size_str = location_and_size_strs[1];

        auto mem_size = static_cast<UINT8>(std::stoul(patch_size_str, &unconverted_idx, 0xa));                       // memory size

        if (std::regex_match(patch_location_str, std::regex("^\\[.+\\]$"))) { // (2)
          auto reg_name = fields[2].substr(1, patch_location_str.size() - 2);
          auto reg = get_pin_register_from_name(reg_name);

          cap_add_patched_indirect_memory_value(ins_addr, exec_order, patch_point, reg, mem_size, patched_value);

          tfm::format(std::cerr, "need to patch memory address pointed by %s of size %d by value 0x%x\n",
                      reg_name, mem_size, patched_value);
        }
        else { // (1)
          auto addr_val_strs = std::vector<std::string>();
          boost::split(addr_val_strs, fields[2], boost::is_any_of(":"), boost::token_compress_on);
          auto mem_addr = static_cast<ADDRINT>(std::stoul(addr_val_strs[0], &unconverted_idx, 16)); // memory address

          cap_add_patched_memory_value(ins_addr, exec_order, patch_point, mem_addr, mem_size, patched_value);

          tfm::format(std::cerr, "need to patch memory address 0x%x of size %d by value 0x%x\n",
                      mem_addr, mem_size, patched_value);
        }
      }
      else { // (3)
        assert(std::count(fields[2].begin(), fields[2].end(), ':') == 2);

        auto reg_lo_hi_pos_strs = std::vector<std::string>{};
        boost::split(reg_lo_hi_pos_strs, fields[2], boost::is_any_of(":"), boost::token_compress_on);
        auto reg_name = reg_lo_hi_pos_strs[0];

        auto reg = get_pin_register_from_name(reg_name);
          auto low_bit_pos = static_cast<UINT8>(std::stoul(reg_lo_hi_pos_strs[1]));
          auto high_bit_pos = static_cast<UINT8>(std::stoul(reg_lo_hi_pos_strs[2]));

        cap_add_patched_register_value(ins_addr, exec_order, patch_point, reg, low_bit_pos, high_bit_pos, patched_value);

        tfm::format(std::cerr, "need to patch %s [%d-%d] with value 0x%x\n",
                    reg_name, low_bit_pos, high_bit_pos, patched_value);
      }
    }
  }
  return;
}


auto get_application_name (int argc, char* argv[]) -> std::string
{
  auto i = int{0};
  for (; i < argc; ++i) if (std::string(argv[i]) == "--") break;
  ASSERTX(i <= (argc - 2));
  return std::string(argv[i + 1]);
}


auto load_configuration_and_options (int argc, char* argv[]) -> void
{
  // initialize trace file, code cache, set start/stop addresses to 0x0
  cap_initialize();

  for (uint32_t i = 0; i < skip_full_address_knob.NumberOfValues(); ++i) {
    pintool_add_caller_skip_address(skip_full_address_knob.Value(i));
  }

  for (uint32_t i = 0; i < skip_auto_address_knob.NumberOfValues(); ++i) {
    pintool_add_callee_skip_addresses(skip_auto_address_knob.Value(i));
  }

  auto app_name = get_application_name(argc, argv);

  auto config_filename = config_file.Value();
  if (config_filename.empty()) {
    config_filename = app_name + ".conf";
    tfm::printfln("the configuration filename is empty, try to guess it from the application name; %s", config_filename);

  }
  tfm::format(std::cerr, "load configuration from file %s...\n", config_filename);
  load_configuration_from_file(config_filename);

  auto option_filename = option_file.Value();
  if (option_filename.empty()) {
    option_filename = app_name + ".opt";
    tfm::printfln("the option filename is empty, try to guess it from the application name: %s", option_filename);
  }
  tfm::format(std::cerr, "load options from file %s...\n", option_filename);
  load_option_from_file(option_filename);

  cap_set_trace_length(trace_length_knob.Value());
  cap_set_loop_count(loop_count_knob.Value());

  cap_initialize_state();

  auto output_filename = output_file.Value();
  if (output_filename.empty()) {
    output_filename = app_name  + ".out";

    tfm::printfln("the output filename is empty, try to guess it from the application name: %s", output_filename);
  }
  cap_parser_initialize(output_filename);

  return;
}

auto stop_pin (INT32 code, VOID* data) -> VOID
{
  static_cast<void>(code); static_cast<void>(data);

  tfm::format(std::cerr, "save trace...\n");
  cap_flush_trace();
  cap_parser_finalize();

  return;
}

auto detach_pin (VOID* data) -> VOID
{
  static_cast<void>(data);

  tfm::format(std::cerr, "save trace...\n");
  cap_flush_trace();
  cap_parser_finalize();

  return;
}

#if defined(_WIN32) || defined(_WIN64)
namespace windows
{
#include <Windows.h>
#include <Psapi.h>
#include <io.h>
#include <fcntl.h>

auto reopen_console () -> void
{
  // attach to the console of the current cmd process
  if (AttachConsole(ATTACH_PARENT_PROCESS))
  {
    auto out_desc = _open_osfhandle(reinterpret_cast<intptr_t>(GetStdHandle(STD_OUTPUT_HANDLE)),
                                    _O_TEXT);
    *stdout = *_fdopen(out_desc, "w"); setvbuf(stdout, NULL, _IONBF, 0);

    auto err_desc = _open_osfhandle(reinterpret_cast<intptr_t>(GetStdHandle(STD_ERROR_HANDLE)),
                                    _O_TEXT);
    *stderr = *_fdopen(err_desc, "w"); setvbuf(stderr, NULL, _IONBF, 0);
  }
  return;
}

} // end of namespace windows
#endif


/*====================================================================================================================*/
/*                                                      main function                                                 */
/*====================================================================================================================*/


auto main(int argc, char* argv[]) -> int
{
#if defined(_WIN32) || defined(_WIN64)
  windows::reopen_console();
#endif

//  for (auto i = int{0}; i < argc; ++i) {
//    tfm::printfln("%s", argv[i]);
//  }
//  return 0;

  // symbol of the binary should be initialized first
  tfm::format(std::cerr, "initialize image symbols...\n");
  PIN_InitSymbols();

  if (PIN_Init(argc, argv)) {
    tfm::format(std::cerr, "%s\n", KNOB_BASE::StringKnobSummary());
    PIN_ExitProcess(PIN_INIT_FAILED);
  }
  else {
    tfm::format(std::cerr, "initialize Pin successfully...\n");

    tfm::format(std::cerr, "load configuration and options...\n");
    load_configuration_and_options(argc, argv);

//    tfm::printfln("add start function...");
//    PIN_AddApplicationStartFunction(load_configuration_and_options, UNUSED_DATA);

//    INS_AddInstrumentFunction(cap_patch_instrunction_information, UNUSED_DATA);
//    INS_AddInstrumentFunction(cap_get_instruction_information, UNUSED_DATA);

    tfm::printfln("pre-processing instructions...");
    IMG_AddInstrumentFunction(cap_img_mode_get_ins_info, UNUSED_DATA);

    tfm::printfln("register trace-based instruction instrumentation...");
//    TRACE_AddInstrumentFunction(cap_trace_mode_patch_ins_info, UNUSED_DATA);
    TRACE_AddInstrumentFunction(cap_trace_mode_get_ins_info, UNUSED_DATA);

//    tfm::format(std::cerr, "register syscall instruction instrumentation...\n");
//    PIN_AddSyscallEntryFunction(cap_get_syscall_entry_info, UNUSED_DATA);
//    PIN_AddSyscallExitFunction(cap_get_syscall_exit_info, UNUSED_DATA);

    tfm::format(std::cerr, "add fini function\n");
    PIN_AddFiniFunction(stop_pin, UNUSED_DATA);
//    PIN_AddDetachFunction(detach_pin, UNUSED_DATA);

    tfm::format(std::cerr, "add follow process function\n");
    PIN_AddFollowChildProcessFunction(proc_follow_process, UNUSED_DATA);

    tfm::format(std::cerr, "pass control to Pin...\n");
    PIN_StartProgram();
  }

  // this return command never executes
  return 0;
}
