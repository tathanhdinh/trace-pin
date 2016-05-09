#include <pin.H>

#include "tracing/tinyformat.h"
#include "tracing/instruction.h"
#include "tracing/export.h"

#include "json.hpp"

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

  // parse "limit trace length"
  std::string limit_length_str = config_json["length"];
  auto limit_length = static_cast<ADDRINT>(std::stoul(limit_length_str, 0, 0));

  pintool_set_trace_limit_length(limit_length);

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

    std::string location_order_str = modify_elem["location"]["order"];
    auto location_order = static_cast<ADDRINT>(std::stoul(location_order_str, 0, 0));

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
        auto modif_reg = get_pin_register_from_name(target_register_str);

        std::string target_value_str = target_elem["value"];
        auto modif_value = static_cast<ADDRINT>(std::stoul(target_value_str, 0, 0));

        pintool_add_register_modifying_point(location_address, location_order, location_position, modif_reg, modif_value);
      }
      else if (target_type_str == "memory") {
        std::string target_memory_str = target_elem["address"];
        auto modif_mem = static_cast<ADDRINT>(std::stoul(target_memory_str, 0, 0));

        std::string target_value_str = target_elem["value"];
        auto modif_value = static_cast<ADDRINT>(std::stoul(target_value_str, 0, 0));

        pintool_add_memory_modifying_point(location_address, location_order, location_position, modif_mem, modif_value);
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
  auto app_name = get_application_name(argc, argv);

  // get configuration file name and parse it
  auto config_filename = config_file.Value();
  if (config_filename.empty()) {
    config_filename = app_name + ".json";
    tfm::printfln("the configuration filename is empty, try to guess it from the application name; %s", config_filename);
  }
  tfm::format(std::cerr, "parse configuration from file %s...\n", config_filename);
  parse_configuration(config_filename);

  // initialize trace file, code cache, set start/stop addresses to 0x0
  initialize_pintool_state();

  auto output_filename = output_file.Value();
  if (output_filename.empty()) {
    output_filename = app_name  + ".out";

    tfm::printfln("the output filename is empty, try to guess it from the application name: %s", output_filename);
  }
  pintool_initialize_trace_file(output_filename);

  return;
}

auto stop_pin (INT32 code, VOID* data) -> VOID
{
  static_cast<void>(code); static_cast<void>(data);

  tfm::format(std::cerr, "save trace...\n");

  pintool_flush_trace();
  pintool_finalize_output_file();

  return;
}

auto detach_pin (VOID* data) -> VOID
{
  static_cast<void>(data);

  tfm::format(std::cerr, "save trace...\n");
  pintool_flush_trace();
  pintool_finalize_output_file();

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
    IMG_AddInstrumentFunction(pintool_img_mode_get_instruction_info, UNUSED_DATA);

    tfm::printfln("register trace-based instruction instrumentation...");
//    TRACE_AddInstrumentFunction(cap_trace_mode_patch_ins_info, UNUSED_DATA);
    TRACE_AddInstrumentFunction(pintool_trace_mode_tracing, UNUSED_DATA);

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
