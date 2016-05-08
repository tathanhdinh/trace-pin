#ifndef CAP_H
#define CAP_H

//#include "../../parsing_helper.h"
#include <cstdint>
#include <pin.H>

// support functions
auto cap_initialize                         ()                                                       -> void;
auto cap_initialize_state                   ()                                                       -> void;
auto cap_set_trace_length                   (uint32_t trace_length)                                  -> void;
auto pintool_set_start_address                  (ADDRINT address)                                        -> void;
auto pintool_set_stop_address                   (ADDRINT address)                                        -> void;
auto cap_add_full_skip_call_address         (ADDRINT address)                                        -> void;
auto cap_add_auto_skip_call_addresses       (ADDRINT address)                                        -> void;
auto cap_set_loop_count                     (uint32_t count)                                         -> void;
auto cap_verify_parameters                  ()                                                       -> void;


auto cap_add_patched_memory_value           (ADDRINT ins_address, UINT32 exec_order, bool be_or_af,
                                             ADDRINT mem_address, UINT8 mem_size, ADDRINT mem_value) -> void;
auto cap_add_patched_register_value         (ADDRINT ins_address, UINT32 exec_order, bool be_or_af,
                                             REG reg, UINT8 lo_pos, UINT8 hi_pos, ADDRINT reg_value) -> void;
auto cap_add_patched_indirect_memory_value  (ADDRINT ins_address, UINT32 exec_order, bool be_or_af,
                                             REG reg, UINT8 mem_size, ADDRINT mem_value)             -> void;

// report functions
auto cap_parser_initialize (const std::string& filename) -> void;
auto cap_flush_trace () -> void;
auto cap_parser_finalize () -> void;

// instrumentation functions
// instruction mode
using ins_instrumentation_t = VOID (*)(INS, VOID*) /*std::add_pointer<VOID(INS, VOID*)>::type*/;
extern ins_instrumentation_t cap_ins_mode_get_ins_info;
extern ins_instrumentation_t cap_patch_instrunction_information;

// trace mode
using trace_instrumentation_t = VOID (*)(TRACE, VOID*);
extern trace_instrumentation_t cap_trace_mode_get_ins_info;
extern trace_instrumentation_t cap_trace_mode_patch_ins_info;

// img mode
using img_instrumentation_t = VOID (*)(IMG, VOID*);
extern img_instrumentation_t cap_img_mode_get_ins_info;

extern SYSCALL_ENTRY_CALLBACK cap_get_syscall_entry_info;
extern SYSCALL_EXIT_CALLBACK cap_get_syscall_exit_info;

// when new process is created/forked
extern auto proc_follow_process (CHILD_PROCESS child_proc, VOID* data) -> bool;

//using syscall_instrumentation_t = VOID (*)(THREADID thread_id, const CONTEXT* p_context, SYSCALL_STANDARD std, VOID* data);
//extern ins_instrumentation_t cap_instrument_instruction_not_follow_call;
// the following functions are generated in compile time by template system
//auto cap_instrument_instruction_follow_call     (INS ins, VOID* data) -> VOID;
//auto cap_instrument_instruction_not_follow_call (INS ins, VOID* data) -> VOID;

#endif
