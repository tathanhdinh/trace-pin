#ifndef CAP_H
#define CAP_H

#include <cstdint>
#include <pin.H>

// support functions
auto initialize_pintool_state () -> void;

auto pintool_set_trace_limit_length (uint32_t trace_length) -> void;

auto pintool_set_chunk_size (uint32_t length) -> void;

auto pintool_set_start_address (ADDRINT address) -> void;
auto pintool_set_stop_address (ADDRINT address) -> void;

auto pintool_add_caller_skip_address   (ADDRINT address) -> void;
auto pintool_add_callee_skip_addresses (ADDRINT address) -> void;

auto pintool_add_memory_modifying_point   (ADDRINT ins_address, UINT32 exec_order, bool modifying_position,
                                           ADDRINT memory_address, ADDRINT modified_value) -> void;
auto pintool_add_register_modifying_point (ADDRINT ins_addr, UINT32 exec_order, bool modifying_position,
                                           REG reg, ADDRINT modified_value) -> void;

// report functions
auto pintool_initialize_trace_file (const std::string& filename) -> void;
auto pintool_flush_trace () -> void;
auto pintool_finalize_output_file () -> void;

// instrumentation functions
// instruction mode
using ins_instrumentation_t = VOID (*)(INS, VOID*) /*std::add_pointer<VOID(INS, VOID*)>::type*/;
extern ins_instrumentation_t pintool_instruction_mode_get_instruction_info;
extern ins_instrumentation_t pintool_instruction_mode_patch_instruction_info;

// trace mode
using trace_instrumentation_t = VOID (*)(TRACE, VOID*);
extern trace_instrumentation_t pintool_trace_mode_tracing;
extern trace_instrumentation_t pintool_trace_mode_modifying;

// img mode
using img_instrumentation_t = VOID (*)(IMG, VOID*);
extern img_instrumentation_t pintool_img_mode_get_instruction_info;

// when new process is created/forked
extern auto proc_follow_process (CHILD_PROCESS child_proc, VOID* data) -> bool;

//using syscall_instrumentation_t = VOID (*)(THREADID thread_id, const CONTEXT* p_context, SYSCALL_STANDARD std, VOID* data);
//extern ins_instrumentation_t cap_instrument_instruction_not_follow_call;
// the following functions are generated in compile time by template system
//auto cap_instrument_instruction_follow_call     (INS ins, VOID* data) -> VOID;
//auto cap_instrument_instruction_not_follow_call (INS ins, VOID* data) -> VOID;

#endif
