
#include <pin.H>

#include "lib/tinyformat.h"
#include "lib/type/instruction.h"
#include "lib/cap/cap.h"

#include <fstream>
#include <boost/algorithm/string.hpp>
#include <algorithm>

#define PIN_INIT_FAILED 1
#define UNUSED_DATA 0

/*====================================================================================================================*/
/*                                                command line handling functions                                     */
/*====================================================================================================================*/


KNOB<string> input_file          (KNOB_MODE_WRITEONCE,
                                  "pintool", "in", "binsec.conf", "input file, for parameterized analysis (patching)");

KNOB<ADDRINT> instruction_check          (KNOB_MODE_WRITEONCE,
                                  "pintool", "ins", "0x1", "Instruction to check");

KNOB<ADDRINT> memory_check  (KNOB_MODE_APPEND,
                                  "pintool", "memory-check", "0x0", "@ of value to check");

KNOB<string> output_file         (KNOB_MODE_WRITEONCE,
                                  "pintool", "out", "values.msg", "output file, to write values into");

/*====================================================================================================================*/
/*                                                     support functions                                              */
/*====================================================================================================================*/

auto get_reg_from_name (const std::string& reg_name) -> REG
{
//  auto upper_reg_name = reg_name;
//  std::transform(reg_name.begin(), reg_name.end(), upper_reg_name.begin(), ::toupper);
  // more simple
  auto upper_reg_name = boost::to_upper_copy(reg_name);
  std::underlying_type<REG>::type reg_id;
  for (reg_id = REG_INVALID_ ; reg_id < REG_LAST; ++reg_id) {
    if (boost::to_upper_copy(REG_StringShort((REG)reg_id)) == upper_reg_name) {
      break;
    }
  }
  return (REG)reg_id;
}


auto load_configuration_from_file (const std::string& filename) -> void
{
  std::ifstream config_file(filename.c_str(), std::ifstream::in);
  auto line = std::string();
  while (std::getline(config_file, line)) {

    line = boost::trim_copy(line);

    if (line.front() != '#') {

      auto field = std::vector<std::string>();
      boost::split(field, line, boost::is_any_of(","), boost::token_compress_on);

      //    tfm::printf("address: %s order: %s info: %s value: %s before/after: %s\n", field[0], field[1], field[2], field[3]);
      //    PIN_ExitProcess(0);

      auto unconverted_idx = std::size_t{0};
      if (std::count(field[2].begin(), field[2].end(), ':') == 1) {

        auto addr_val_strs = std::vector<std::string>();
        boost::split(addr_val_strs, field[2], boost::is_any_of(":"), boost::token_compress_on);

        cap_add_patched_memory_value(std::stoul(field[0], &unconverted_idx, 16),         // address of the instruction
                                     std::stoul(field[1]),                               // execution order
                                     (field[4] == "1"),                                  // patching point (false = before, true = after)
                                     std::stoul(addr_val_strs[0], &unconverted_idx, 16), // memory address
                                     std::stoul(addr_val_strs[1]),                       // memory size
                                     std::stoul(field[3], &unconverted_idx, 16)          // memory value
                                     );
        tfm::printf("need to patch memory address %s of size %d by value %s\n",
                    StringFromAddrint(std::stoul(addr_val_strs[0], &unconverted_idx, 16)),
                    std::stoul(addr_val_strs[1]),
                    StringFromAddrint(std::stoul(field[3], &unconverted_idx, 16)));
      }
      else {
        assert(std::count(field[2].begin(), field[2].end(), ':') == 2);

        auto reg_lo_hi_pos_strs = std::vector<std::string>();
        boost::split(reg_lo_hi_pos_strs, field[2], boost::is_any_of(":"), boost::token_compress_on);

        cap_add_patched_register_value(std::stoul(field[0], &unconverted_idx, 16), // address of the instruction
                                       std::stoul(field[1]),                       // execution order of the instruction
                                       (field[4] == "1"),                          // patching point (false = before, true = after)
                                       get_reg_from_name(reg_lo_hi_pos_strs[0]),   // register name
                                       std::stoul(reg_lo_hi_pos_strs[1]),          // low bit position
                                       std::stoul(reg_lo_hi_pos_strs[2]),          // hight bit position
                                       std::stoul(field[3], &unconverted_idx, 16)  // register value
                                       );

        tfm::printf("need to patch %s [%s-%s] with value %d\n",
                    reg_lo_hi_pos_strs[0], reg_lo_hi_pos_strs[1], reg_lo_hi_pos_strs[2],
                    std::stoul(field[3], &unconverted_idx, 16));
      }
    }
  }
  return;
}


auto start_pin (VOID* data) -> VOID
{
  load_configuration_from_file(input_file.Value());
  return;
}


ADDRINT addr;
ADDRINT *vals;

auto read_vals()
{
  ofstream file;
	ostringstream filename;
	filename<< "symbolic_read/0x" << hex << addr ;
  file.open (filename.str());
	ADDRINT val;
	ADDRINT *addr_check	;
	for (uint32_t i = 0; i < memory_check.NumberOfValues(); ++i) {
		addr_check=(ADDRINT*)memory_check.Value(i);
		PIN_SafeCopy(&val,addr_check , sizeof(ADDRINT));
		file << hex << addr_check;
		file << ":0x" << hex <<val<< "\n"; 
	}
  file.close();
}


auto check_values(TRACE trace, VOID *data)
{
  for (auto bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
    for (auto ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
			if(INS_Address(ins)==addr)//0x8048449)
				INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)read_vals,IARG_END);
    }
  }
  return;
}

/*====================================================================================================================*/
/*                                                      main function                                                 */
/*====================================================================================================================*/


auto main(int argc, char* argv[]) -> int
{
  // symbol of the binary should be initialized first
  tfm::format(std::cerr, "initialize image symbols...\n");
  PIN_InitSymbols();

	

  if (PIN_Init(argc, argv)) {
    tfm::format(std::cerr, "%s\n", KNOB_BASE::StringKnobSummary());
    PIN_ExitProcess(PIN_INIT_FAILED);
  }
  else {
    tfm::format(std::cerr, "initialize Pin success...\n");
    
    tfm::format(std::cerr, "add callback functions...\n");
    PIN_AddApplicationStartFunction(start_pin, UNUSED_DATA);
    
    TRACE_AddInstrumentFunction(cap_trace_mode_patch_ins_info, UNUSED_DATA);
		
//		vals=malloc(sizeof(ADDRINT) * memory_check.NumberOfValues());
		for (uint32_t i = 0; i < memory_check.NumberOfValues(); ++i) {
//			vals[i]=memory_check.Value(i);
		}
		
		addr=instruction_check.Value();
		TRACE_AddInstrumentFunction(check_values, &addr);
    
    tfm::format(std::cerr, "pass control to Pin\n");
    PIN_StartProgram();
  }

  // this return command never executes
  return 0;
}
