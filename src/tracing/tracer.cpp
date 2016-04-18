#include "export.h"
#include "common.h"

//#include "../framework/analysis_callback.h"

#include "tinyformat.h"

#include <limits>
#include <cassert>
#include <bitset>
#include <functional>

#include <boost/type_traits.hpp>
#include <typeinfo>

using ins_callback_func_t = VOID(*)(INS ins, IPOINT ipoint, AFUNPTR funptr, ...);

template <bool use_predicated_callback>
ins_callback_func_t ins_insert_call;

template <>
static auto ins_insert_call<true> = INS_InsertPredicatedCall;

template <>
static auto ins_insert_call<false> = INS_InsertCall;

enum tracing_state_t
{
  NOT_STARTED         = 0,
  FULL_SUSPENDED      = 1,
  ENABLED             = 3,
  DISABLED            = 4
};

using syscall_info_t = std::tuple<
  ADDRINT, // syscall number
  ADDRINT, // return value
  ADDRINT, // 1st argument
  ADDRINT, // 2nd
  ADDRINT, // 3rd
  ADDRINT  // 4th
  >;

enum
  {
    SYSCALL_ID    = 0,
    SYSCALL_RET   = 1,
    SYSCALL_ARG_0 = 2,
    SYSCALL_ARG_1 = 3,
    SYSCALL_ARG_2 = 4,
    SYSCALL_ARG_3 = 5
  };

// for patching
using exec_point_t                  = std::pair<ADDRINT, UINT32>;
using patch_point_t                 = std::pair<exec_point_t, bool>;

using register_patch_value_t        = std::tuple<REG,     // patched register
                                                 UINT8,   // low bit position
                                                 UINT8,   // high bit position
                                                 ADDRINT  // value need to be set
                                                 >;

using memory_patch_value_t          = std::tuple<ADDRINT, // patched memory address
                                                 UINT8,   // patched size
                                                 ADDRINT  // value need to be set
                                                 >;

using indirect_memory_patch_value_t = std::tuple<REG,     // register containinng patched memory address
                                                 UINT8,   // patched size
                                                 ADDRINT  // value need to be set
                                                 >;

using patch_point_register_t        = std::pair<patch_point_t, register_patch_value_t>;
using patch_point_memory_t          = std::pair<patch_point_t, memory_patch_value_t>;
using patch_point_indirect_memory_t = std::pair<patch_point_t, indirect_memory_patch_value_t>;

// using auto here is not supported by C++11 standard (why?)
dyn_inss_t trace                             = dyn_inss_t();
map_address_instruction_t cached_ins_at_addr = map_address_instruction_t();

static auto state_of_thread                    = std::map<THREADID, tracing_state_t>();
static auto ins_at_thread                      = std::map<THREADID, dyn_ins_t>();
static auto resume_address_of_thread           = std::map<THREADID, ADDRINT>();

static auto start_address                      = ADDRINT{0};
static auto stop_address                       = ADDRINT{0};
static auto full_skip_call_addresses           = std::vector<ADDRINT>();
//static auto selective_skip_call_addresses      = std::vector<ADDRINT>();
static auto auto_skip_call_addresses           = std::vector<ADDRINT>();
static auto max_trace_length                   = uint32_t{0};
static auto loop_count                         = uint32_t{0};
static auto trace_length                       = uint32_t{0};

static auto patched_register_at_address        = std::vector<patch_point_register_t>();
static auto patched_memory_at_address          = std::vector<patch_point_memory_t>();
static auto patched_indirect_memory_at_address = std::vector<patch_point_indirect_memory_t>();
static auto execution_order_of_address         = std::map<ADDRINT, UINT32>();

//static auto current_syscall_info               = syscall_info_t();

static auto some_thread_is_started             = false;
static auto some_thread_is_not_suspended       = true;

/*====================================================================================================================*/
/*                                       callback analysis and support functions                                      */
/*====================================================================================================================*/


enum event_t
{
  NEW_THREAD          = 0,
  ENABLE_TO_SUSPEND   = 1,
  ANY_TO_DISABLE      = 2,
  ANY_TO_TERMINATE    = 3,
  NOT_START_TO_ENABLE = 4,
  SUSPEND_TO_ENABLE   = 5
};


static auto reinstrument_if_some_thread_started (ADDRINT current_addr,
                                                 ADDRINT next_addr, const CONTEXT* p_ctxt) -> void
{
//  assert(current_addr != start_address);
  ASSERTX(!some_thread_is_started);

  if (cached_ins_at_addr[current_addr]->is_ret) {
//    ASSERTX(PIN_GetContextReg(p_ctxt, REG_STACK_PTR) == next_addr);

    auto return_addr = next_addr;
    PIN_SafeCopy(&return_addr, reinterpret_cast<ADDRINT*>(next_addr), sizeof(ADDRINT));
    next_addr = return_addr;
  }

  if (next_addr == start_address) {
    some_thread_is_started = true;

    tfm::format(std::cerr, "the next executed instruction is at %s (current %s), restart instrumentation...\n",
                StringFromAddrint(next_addr), StringFromAddrint(current_addr));

    PIN_RemoveInstrumentation();
//    CODECACHE_InvalidateTraceAtProgramAddress(start_address);
//    CODECACHE_InvalidateRange(start_address, stop_address);
//    CODECACHE_FlushCache();
    PIN_ExecuteAt(p_ctxt);
  }
  return;
}


static auto update_skip_addresses(ADDRINT ins_addr, ADDRINT target_addr) -> void
{
  if ((std::find(std::begin(full_skip_call_addresses),
                 std::end(full_skip_call_addresses), ins_addr) == std::end(full_skip_call_addresses)) &&
      (std::find(std::begin(auto_skip_call_addresses),
                std::end(auto_skip_call_addresses), target_addr) != std::end(auto_skip_call_addresses))) {

    tfm::format(std::cerr, "add a full-skip at 0x%x  %s from an auto-skip at 0x%x\n",
                ins_addr, cached_ins_at_addr[ins_addr]->disassemble, target_addr);

    full_skip_call_addresses.push_back(ins_addr);
  }
  return;
}


static auto reinstrument_because_of_suspended_state (const CONTEXT* p_ctxt, ADDRINT ins_addr) -> void
{
  auto new_state = std::any_of(std::begin(state_of_thread), std::end(state_of_thread),
                               [](decltype(state_of_thread)::const_reference thread_state) {
      static_assert(std::is_same<decltype(std::get<1>(thread_state)), const tracing_state_t&>::value, "type conflict");

      return (std::get<1>(thread_state) != FULL_SUSPENDED);
  });

  if (new_state != some_thread_is_not_suspended) {
    some_thread_is_not_suspended = new_state;

    tfm::format(std::cerr, "state changed to %s, restart instrumentation...\n",
                !some_thread_is_not_suspended ? "suspend" : "enable");
//    cap_flush_trace();

    PIN_RemoveInstrumentation();
    PIN_ExecuteAt(p_ctxt);
//    CODECACHE_FlushCache();
  }

  return;
}


template <event_t event>
static auto update_condition (ADDRINT ins_addr, THREADID thread_id) -> void
{
  static_assert((event == NEW_THREAD) || (event == ENABLE_TO_SUSPEND) ||
                (event == ANY_TO_DISABLE) || (event == ANY_TO_TERMINATE) ||
                (event == NOT_START_TO_ENABLE) || (event == SUSPEND_TO_ENABLE), "unknow event");

  switch (event) {
  case NEW_THREAD:
    if (state_of_thread.find(thread_id) == state_of_thread.end()) {
      state_of_thread[thread_id] = NOT_STARTED;
    }
    break;

  case ENABLE_TO_SUSPEND:
    if (ins_at_thread.find(thread_id) != ins_at_thread.end()) {
      if (state_of_thread[thread_id] == ENABLED) {

        auto thread_ins_addr = std::get<INS_ADDRESS>(ins_at_thread[thread_id]);

        if (std::find(
              std::begin(full_skip_call_addresses), std::end(full_skip_call_addresses), thread_ins_addr)
            != std::end(full_skip_call_addresses)) {

          tfm::format(std::cerr, "suspend thread %d...\n", thread_id);

          state_of_thread[thread_id] = FULL_SUSPENDED;
        }

        if ((std::get<INS_ADDRESS>(ins_at_thread[thread_id]) == stop_address) && (stop_address != 0x0)) {
          state_of_thread[thread_id] = FULL_SUSPENDED;
        }
      }
    }
    break;

  case ANY_TO_DISABLE:
    if (ins_at_thread.find(thread_id) != ins_at_thread.end()) {
      if ((state_of_thread[thread_id] != NOT_STARTED) && (state_of_thread[thread_id] != DISABLED)) {

        if ((std::get<INS_ADDRESS>(ins_at_thread[thread_id]) == stop_address) && (stop_address != 0x0)) {
          loop_count--;
          if (loop_count <= 0) state_of_thread[thread_id] = DISABLED;
        }
      }
    }
    break;

  case ANY_TO_TERMINATE:
    if (std::all_of(std::begin(state_of_thread), std::end(state_of_thread),
                    [](decltype(state_of_thread)::const_reference thread_state)
                    { return (std::get<1>(thread_state) == DISABLED); })) {
      tfm::format(std::cerr, "all execution threads are terminated, exit application...\n");
      PIN_ExitApplication(1);
    }
    break;

  case NOT_START_TO_ENABLE:
    if (((ins_addr == start_address) || (start_address == 0x0)) && (state_of_thread[thread_id] == NOT_STARTED)) {
      state_of_thread[thread_id] = ENABLED;
    }
    break;

  case SUSPEND_TO_ENABLE:
    if (state_of_thread[thread_id] == FULL_SUSPENDED) {

      if (ins_addr == resume_address_of_thread[thread_id]) {
        tfm::format(std::cerr, "enable thread %d...\n", thread_id);

        state_of_thread[thread_id] = ENABLED;
      }

      if (ins_addr == start_address) {
        tfm::format(std::cerr, "enable thread %d...\n", thread_id);

        state_of_thread[thread_id] = ENABLED;
      }
    }
    break;
  }

  return;
}


static auto initialize_instruction (ADDRINT ins_addr, THREADID thread_id) -> void
{
  if (state_of_thread[thread_id] == ENABLED) {

    ins_at_thread[thread_id] = dyn_ins_t(ins_addr,          // instruction address
                                         thread_id,         // thread id
                                         dyn_regs_t(),      // read registers
                                         dyn_regs_t(),      // written registers
                                         dyn_mems_t(),      // read memory addresses
                                         dyn_mems_t()       // write memory addresses
                                         );
  }
  return;
}


static auto update_resume_address (ADDRINT resume_addr, THREADID thread_id) -> void
{
  ASSERTX(state_of_thread.find(thread_id) != state_of_thread.end());

  if (state_of_thread[thread_id] == ENABLED) {
    resume_address_of_thread[thread_id] = resume_addr;
  }
  return;
}


template <bool read_or_write>
static auto save_register (const CONTEXT* p_context, THREADID thread_id) -> void
{
  if (ins_at_thread.find(thread_id) != ins_at_thread.end()) {

    auto ins_addr = std::get<INS_ADDRESS>(ins_at_thread[thread_id]);
    const auto & current_ins = cached_ins_at_addr[ins_addr];

    if ((state_of_thread[thread_id] == ENABLED) && !current_ins->is_special) {

      const auto & regs = !read_or_write ? current_ins->src_registers :
                                           current_ins->dst_registers;

      auto & reg_map = !read_or_write ? std::get<INS_READ_REGS>(ins_at_thread[thread_id]) :
                                        std::get<INS_WRITE_REGS>(ins_at_thread[thread_id]);

      for (auto const& reg : regs) {
        PIN_REGISTER reg_value;
        PIN_GetContextRegval(p_context, reg, reinterpret_cast<uint8_t*>(&reg_value));
        reg_map[reg] = reg_value;
      }
    }
  }

  return;
}

enum rw_t { READ = 0, WRITE = 1 };

template <rw_t read_or_write>
static auto save_memory (ADDRINT mem_addr, UINT32 mem_size, THREADID thread_id) -> void
{
  static_assert((read_or_write == READ) || (read_or_write == WRITE), "unknown action");

  if (ins_at_thread.find(thread_id) != ins_at_thread.end()) {

    if (state_of_thread[thread_id] == ENABLED) {

      // any chance for compile time evaluation !?
      auto& mem_map = (read_or_write == READ) ? std::get<INS_READ_MEMS>(ins_at_thread[thread_id]) :
                                                std::get<INS_WRITE_MEMS>(ins_at_thread[thread_id]);

      if (mem_addr != 0) {
        for (decltype(mem_size) idx = 0; idx < mem_size; ++idx) {
          mem_map[mem_addr + idx] = *(reinterpret_cast<uint8_t*>(mem_addr + idx));
        }
      }

    }
  }

  return;
}


static auto add_to_trace (ADDRINT ins_addr, THREADID thread_id) -> void
{
  static_cast<void>(ins_addr);

  if (ins_at_thread.find(thread_id) != ins_at_thread.end() &&
      state_of_thread[thread_id] == ENABLED) {

    if (trace.size() >= 5000) {
        trace_length += trace.size();

        if (trace_length >= max_trace_length) {
          tfm::format(std::cerr, "stop tracing since trace limit length %d is exceed\n", max_trace_length);

          PIN_ExitApplication(1);
        }

        cap_flush_trace();
      }
  }

  return;
}


static auto remove_previous_instruction (THREADID thread_id) -> void
{
  if (ins_at_thread.find(thread_id) != ins_at_thread.end()) {
    ins_at_thread.erase(thread_id);
  }
  return;
}


static auto update_execution_order (ADDRINT ins_addr, THREADID thread_id) -> void
{
  static_cast<void>(thread_id);

  static auto last_updated_address = ADDRINT{0x0};

  // this verification is erronous in case of rep instructions (so we should not patch at them)
  if (last_updated_address != ins_addr) {
    execution_order_of_address[ins_addr]++;
  }
  last_updated_address = ins_addr;
  return;
}


template<typename reg_value_type>
static auto patch_register_of_type (ADDRINT org_patch_val,
                                    uint8_t val_lo_pos, uint8_t val_hi_pos,
                                    PIN_REGISTER* p_pin_reg) -> void
{
  auto reg_patch_val = org_patch_val << val_lo_pos;
  auto patch_val_bitsec = std::bitset<std::numeric_limits<reg_value_type>::digits>(reg_patch_val);

  auto pin_current_val = *(reinterpret_cast<reg_value_type*>(p_pin_reg));
  auto current_val_bitset = std::bitset<numeric_limits<reg_value_type>::digits>(pin_current_val);

  for (auto i = 0; i < std::numeric_limits<reg_value_type>::digits; ++i) {
    if ((i < val_lo_pos) || (i > val_hi_pos)) patch_val_bitsec[i] = current_val_bitset[i];
  }

  tfm::format(std::cerr, "value before patching = 0x%x\n", pin_current_val);
  *(reinterpret_cast<reg_value_type*>(p_pin_reg)) = patch_val_bitsec.to_ulong();
  tfm::format(std::cerr, "value after patching = 0x%x\n", *(reinterpret_cast<reg_value_type*>(p_pin_reg)));
  return;
}


static auto patch_register (ADDRINT ins_addr, bool patch_point,
                            UINT32 patch_reg, PIN_REGISTER* p_register,
                            THREADID thread_id) -> void
{
  (void)thread_id;
  ASSERTX(REG_valid(static_cast<REG>(patch_reg)) && "the needed to patch register is invalid");

  static auto patch_reg_funs = std::map<
      uint8_t, std::function<void(ADDRINT, uint8_t, uint8_t, PIN_REGISTER*)>
      > {
    {1, patch_register_of_type<uint8_t>}, {2, patch_register_of_type<uint16_t>},
    {4, patch_register_of_type<uint32_t>}, {8, patch_register_of_type<uint64_t>}
  };

  for (auto const& patch_reg_info : patched_register_at_address) {

    auto patch_exec_point  = std::get<0>(patch_reg_info);
    auto patch_reg_value = std::get<1>(patch_reg_info);

    auto exec_point        = std::get<0>(patch_exec_point);
    auto exec_addr         = std::get<0>(exec_point);
    auto exec_order        = std::get<1>(exec_point);
    auto found_patch_point = std::get<1>(patch_exec_point);
    auto found_patch_reg   = std::get<0>(patch_reg_value);

    ASSERTX(REG_valid(found_patch_reg) && "the patched register is invalid");

    if ((exec_addr == ins_addr) && (exec_order == execution_order_of_address[ins_addr]) &&
        (found_patch_point == patch_point) && (found_patch_reg == patch_reg)) {

      auto reg_info        = std::get<1>(patch_reg_info);
      auto reg_size        = static_cast<uint8_t>(REG_Size(std::get<0>(reg_info)));
      auto reg_lo_pos      = std::get<1>(reg_info);
      auto reg_hi_pos      = std::get<2>(reg_info);
      auto reg_patch_val   = std::get<3>(reg_info);

      patch_reg_funs[reg_size](reg_patch_val, reg_lo_pos, reg_hi_pos, p_register);
    }
  }

  return;
}


/*
 * Because the thread_id is not used in this function, the memory patching is realized actually by any thread.
 */
static auto patch_memory (ADDRINT ins_addr, bool patch_point,
                          ADDRINT patch_mem_addr, THREADID thread_id) -> void
{
  static_cast<void>(thread_id);

  for (auto const& patch_mem_info : patched_memory_at_address) {

    auto patch_exec_point  = std::get<0>(patch_mem_info);
    auto exec_point        = std::get<0>(patch_exec_point);
    auto exec_addr         = std::get<0>(exec_point);
    auto exec_order        = std::get<1>(exec_point);
    auto exec_patch_point  = std::get<1>(patch_exec_point);

    auto patch_mem_val = std::get<1>(patch_mem_info);
    auto found_mem_addr = std::get<0>(patch_mem_val);

    if ((exec_addr == ins_addr) && (exec_order == execution_order_of_address[ins_addr]) &&
        (exec_patch_point == patch_point) && (found_mem_addr == patch_mem_addr)) {

      auto mem_size  = std::get<1>(patch_mem_val);
      auto mem_value = std::get<2>(patch_mem_val);

      tfm::format(std::cerr, "at 0x%x: will patch %d bytes at 0x%x by value 0x%x\n", exec_addr,
                    mem_size, found_mem_addr, mem_value);

      auto excp_info = EXCEPTION_INFO();
      auto patched_mem_size = PIN_SafeCopyEx(reinterpret_cast<uint8_t*>(found_mem_addr),
                                             reinterpret_cast<uint8_t*>(&mem_value), mem_size, &excp_info);
      if (patched_mem_size != mem_size) {
        tfm::format(std::cerr, "error: %s\n", PIN_ExceptionToString(&excp_info));
      }
      else {
        tfm::format(std::cerr, "after patching: ADDRINT value at 0x%x is 0x%x\n", found_mem_addr,
                    *reinterpret_cast<ADDRINT*>(found_mem_addr));
      }
    }
  }
  return;
}


static auto patch_indirect_memory (ADDRINT ins_addr, bool patch_point,
                                   UINT32 patch_indirect_reg, ADDRINT patch_indirect_addr, THREADID thread_id) -> void
{
  static_cast<void>(thread_id);
  ASSERTX(REG_valid(static_cast<REG>(patch_indirect_reg)) && "the patched register is invalid");

  for (auto const& patch_indirect_mem_info : patched_indirect_memory_at_address) {
    auto patch_exec_point = std::get<0>(patch_indirect_mem_info);
    auto exec_point       = std::get<0>(patch_exec_point);
    auto exec_addr        = std::get<0>(exec_point);
    auto exec_order       = std::get<1>(exec_point);
    auto patch_pos        = std::get<1>(patch_exec_point); // before or after

    auto patch_indirect_info = std::get<1>(patch_indirect_mem_info);
    auto need_to_patch_indirect_reg   = std::get<0>(patch_indirect_info);

    if ((exec_addr == ins_addr) && (exec_order == execution_order_of_address[ins_addr]) &&
        (patch_pos == patch_point) && (need_to_patch_indirect_reg == patch_indirect_reg)) {

      auto mem_size = std::get<1>(patch_indirect_info);
      auto mem_value = std::get<2>(patch_indirect_info);

      tfm::format(std::cerr, "at 0x%x: will patch %d bytes at 0x%x by value 0x%x\n",
                  exec_addr, mem_size, patch_indirect_addr, mem_value);

      auto excp_info = EXCEPTION_INFO();
      auto patched_mem_size = PIN_SafeCopyEx(reinterpret_cast<uint8_t*>(patch_indirect_addr),
                                             reinterpret_cast<uint8_t*>(&mem_value), mem_size, &excp_info);
      if (patched_mem_size != mem_size) {
        tfm::format(std::cerr, "error: %s\n", PIN_ExceptionToString(&excp_info));
      }
      else {
        tfm::format(std::cerr, "after patching: ADDRINT value at 0x%x is 0x%x\n",
                    patch_indirect_addr, *reinterpret_cast<ADDRINT*>(patch_indirect_addr));
      }
    }
  }

  return;
}

//static auto save_before_handling (INS ins) -> void
//{
//  static_assert(std::is_same<
//                decltype(save_register<WRITE>), VOID (const CONTEXT*, UINT32)
//                >::value, "invalid callback function type");

//  auto ins_address = INS_Address(ins);
//  ASSERTX(!cached_ins_at_addr[ins_address]->is_special);

//  ins_insert_call<false>(ins, IPOINT_BEFORE, reinterpret_cast<AFUNPTR>(save_register<WRITE>),
//                        IARG_CONST_CONTEXT,
//                        IARG_THREAD_ID,
//                        IARG_END);

//  static_assert(std::is_same<
//                decltype(save_memory<WRITE>), VOID (ADDRINT, UINT32, UINT32)
//                >::value, "invalid callback function type");

//  ins_insert_call<false>(ins, IPOINT_BEFORE, reinterpret_cast<AFUNPTR>(save_memory<WRITE>),
//                        IARG_ADDRINT, 0,
//                        IARG_UINT32, 0,
//                        IARG_THREAD_ID,
//                        IARG_END);
//  return;
//}


static auto update_condition_before_handling (INS ins) -> void
{
  static_assert(std::is_same<
                decltype(update_condition<ANY_TO_DISABLE>), VOID (ADDRINT, UINT32)
                >::value, "invalid callback function type");

  ins_insert_call<false>(ins, IPOINT_BEFORE, reinterpret_cast<AFUNPTR>(update_condition<ANY_TO_DISABLE>),
                        IARG_INST_PTR,
                        IARG_THREAD_ID,
                        IARG_END);

  ins_insert_call<false>(ins, IPOINT_BEFORE, reinterpret_cast<AFUNPTR>(update_condition<ANY_TO_TERMINATE>),
                        IARG_INST_PTR,
                        IARG_THREAD_ID,
                        IARG_END);

  ins_insert_call<false>(ins, IPOINT_BEFORE, reinterpret_cast<AFUNPTR>(update_condition<ENABLE_TO_SUSPEND>),
                        IARG_INST_PTR,
                        IARG_THREAD_ID,
                        IARG_END);

  ins_insert_call<false>(ins, IPOINT_BEFORE, reinterpret_cast<AFUNPTR>(update_condition<NOT_START_TO_ENABLE>),
                        IARG_INST_PTR,
                        IARG_THREAD_ID,
                        IARG_END);

  ins_insert_call<false>(ins, IPOINT_BEFORE, reinterpret_cast<AFUNPTR>(update_condition<SUSPEND_TO_ENABLE>),
                        IARG_INST_PTR,
                        IARG_THREAD_ID,
                        IARG_END);
  return;
}


static auto insert_ins_get_info_callbacks (INS ins) -> void
{
  auto ins_addr = INS_Address(ins);

  /*
   * Update the code cache if a new instruction found (be careful for self-modifying code)
   */
  if (cached_ins_at_addr.find(ins_addr) == cached_ins_at_addr.end()) {
    cached_ins_at_addr[ins_addr] = std::make_shared<instruction>(ins);
  }

  // current instruction
  auto current_ins = cached_ins_at_addr[ins_addr];

  // runtime skip checking
  if (current_ins->is_call) {
    static_assert(std::is_same<decltype (update_skip_addresses), VOID (ADDRINT, ADDRINT)
                  >::value, "invalid callback function type");

    ins_insert_call<false>(ins, IPOINT_BEFORE, reinterpret_cast<AFUNPTR>(update_skip_addresses),
                          IARG_INST_PTR,
                          IARG_BRANCH_TARGET_ADDR,
                          IARG_END);
  }


  if (some_thread_is_started) {
    // we must always verify whether there is a new execution thread or not
    static_assert(std::is_same<
                  decltype(update_condition<NEW_THREAD>), VOID (ADDRINT, THREADID)
                  >::value, "invalid callback function type");

    ins_insert_call<false>(ins, IPOINT_BEFORE, reinterpret_cast<AFUNPTR>(update_condition<NEW_THREAD>),
                          IARG_INST_PTR,
                          IARG_THREAD_ID,
                          IARG_END);

    /*
     * The write memory addresses/registers of the PREVIOUS instruction are collected in the following callback analysis
     * functions.
     *
     * We note that these functions capture information of normal instructions. The syscalls need some more special
     * treatment because the read/write memory addresses/registers cannot be determined statically.
     */

//    if (some_thread_is_not_suspended) {
//      // update information of the PREVIOUS instruction (i.e. write registers, memory addresses)
//      if (!current_ins->is_special) {
//        save_before_handling(ins);
//      }
//    }

    // add the PREVIOUS instruction into the trace.
    if (some_thread_is_not_suspended) {
      static_assert(std::is_same<
                    decltype(add_to_trace), VOID (ADDRINT, UINT32)
                    >::value, "invalid callback function type");

      ins_insert_call<false>(ins, IPOINT_BEFORE, reinterpret_cast<AFUNPTR>(add_to_trace),
                            IARG_INST_PTR,
                            IARG_THREAD_ID,
                            IARG_END);

    }

    /*
     * The following state update callback functions are CALLED ALWAYS, even when all threads are suspended. These
     * functions need to detect if there is some thread goes out of the suspended state.
     */
    update_condition_before_handling(ins);

    /*
     * The following callback function is called only if there is some non-suspended state, if all states are suspended
     * then the skip addresses are not interesting.
     */

    if (some_thread_is_not_suspended) {

      auto current_ins_addr = current_ins->address;

      if (std::find(std::begin(full_skip_call_addresses), std::end(full_skip_call_addresses), current_ins_addr)
          != std::end(full_skip_call_addresses)) {
        static_assert(std::is_same<
                      decltype(update_resume_address), VOID (ADDRINT, UINT32)
                      >::value, "invalid callback function type");

        ins_insert_call<false>(ins,
                              IPOINT_BEFORE,
                              reinterpret_cast<AFUNPTR>(update_resume_address),
                              IARG_ADDRINT, current_ins->next_address,
                              IARG_THREAD_ID,
                              IARG_END);
      }
    } // end of if (some_thread_is_not_suspended)

    if (some_thread_is_not_suspended) {
      ins_insert_call<false>(ins,
                            IPOINT_BEFORE,
                            reinterpret_cast<AFUNPTR>(remove_previous_instruction),
                            IARG_THREAD_ID,
                            IARG_END);
    }

    /*
     * The state is updated previously (before capturing instruction's information). Now we will verify if the state
     * leads to a reinstrumentation or not. We note that if the following callback function restarts the instrumentation,
     * then the callback functions after it may not be called. In general, the instrumentation will restart from
     * the beginning of this intrumentation function.
     *
     * We note that this callback function will change value of the identifier "some_thread_is_not_suspended", and it
     * explicitly makes callback functions after it be called or not
     */

    static_assert(std::is_same<
                  decltype(reinstrument_because_of_suspended_state), VOID (const CONTEXT*, ADDRINT)
                  >::value, "invalid callback function type");

      // ATTENTION: cette fonction pourra changer l'instrumentation!!!!
    ins_insert_call<false>(ins,
                          IPOINT_BEFORE,
                          reinterpret_cast<AFUNPTR>(reinstrument_because_of_suspended_state),
                          IARG_CONST_CONTEXT,
                          IARG_INST_PTR,
                          IARG_END);

    /*
     * The function ABOVE will update the suspended state (which is true if there is some non-suspended thread, and
     * false if all threads are suspended), and restart the instrumentation only if the suspended state changes.
     *
     * Now if the following callback functions are called, then that means the instruction should be captured. The
     * following function will capture information of the current instruction.
     */

    if (some_thread_is_not_suspended) {

      // initialize and save information of the CURRENT instruction

      static_assert(std::is_same<
                    decltype(initialize_instruction), VOID (ADDRINT, UINT32)
                    >::value, "invalid callback function type");

      ins_insert_call<false>(ins,                                               // instrumented instruction
                            IPOINT_BEFORE,                                     // instrumentation point
                            reinterpret_cast<AFUNPTR>(initialize_instruction), // callback analysis function
                            IARG_INST_PTR,                                     // instruction address
                            IARG_THREAD_ID,                                    // thread id
                            IARG_END);

#if defined(FAST_TRACING)
#else
      if (!current_ins->src_registers.empty()) {

        static_assert(std::is_same<
                      decltype(save_register<READ>), VOID (const CONTEXT*, UINT32)
                      >::value, "invalid callback function type");

        ins_insert_call<false>(ins,                                            // instrumented instruction
                              IPOINT_BEFORE,                                  // instrumentation point
                              reinterpret_cast<AFUNPTR>(save_register<READ>), // callback analysis function
                              IARG_CONST_CONTEXT,                             // context of CPU,
                              IARG_THREAD_ID,                                 // thread id
                              IARG_END);
      }

      if (!current_ins->dst_registers.empty()) {
        ins_insert_call<false>(ins,
                              IPOINT_AFTER,
                              reinterpret_cast<AFUNPTR>(save_register<WRITE>),
                              IARG_CONST_CONTEXT,
                              IARG_THREAD_ID,
                              IARG_END);
      }

      if (current_ins->is_memory_read) {

        static_assert(std::is_same<
                      decltype(save_memory<READ>), VOID (ADDRINT, UINT32, UINT32)
                      >::value, "invalid callback function type");

        ins_insert_call<false>(ins,                                          // instrumented instruction
                              IPOINT_BEFORE,                                // instrumentation point
                              reinterpret_cast<AFUNPTR>(save_memory<READ>), // callback analysis function (read)
                              IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE,     // memory read (address, size)
                              IARG_THREAD_ID,                               // thread id
                              IARG_END);
      }

      if (current_ins->has_memory_read_2) {

        ins_insert_call<false>(ins,                                          // instrumented instruction
                              IPOINT_BEFORE,                                // instrumentation point
                              reinterpret_cast<AFUNPTR>(save_memory<READ>), // callback analysis function (read)
                              IARG_MEMORYREAD2_EA, IARG_MEMORYREAD_SIZE,    // memory read (address, size)
                              IARG_THREAD_ID,                               // thread id
                              IARG_END);
      }

      if (current_ins->is_memory_write) {

        ins_insert_call<false>(ins,                                           // instrumented instruction
                              IPOINT_AFTER,                                  // instrumentation point
                              reinterpret_cast<AFUNPTR>(save_memory<WRITE>), // callback analysis function (write)
                              IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE,    // memory written (address, size)
                              IARG_THREAD_ID,                                // thread id
                              IARG_END);
      }
#endif
    }
  }
  else { // !some_thread_is_started

    /*
     * The following callback functions will restart the instrumentation if the next executed instruction is the
     * start instruction. They are also the only analysis functions called when the start instruction is not executed.
     *
     * We DO NOT NEED to give too much attention at these functions, because they are never re-executed. The value
     * of the identified some_thread_is_started is changed only one time.
     */

    if (!current_ins->is_special) {
      if (current_ins->is_call || current_ins->is_branch) {
        static_assert(std::is_same<
                      decltype(reinstrument_if_some_thread_started), VOID (ADDRINT, ADDRINT, const CONTEXT*)
                      >::value, "invalid callback function type");

        ins_insert_call<false>(ins,
                              IPOINT_BEFORE,
                              reinterpret_cast<AFUNPTR>(reinstrument_if_some_thread_started),
                              IARG_INST_PTR,
                              IARG_BRANCH_TARGET_ADDR,
                              IARG_CONST_CONTEXT,
                              IARG_END);
      }
      else {
        if (current_ins->is_ret) {
          ins_insert_call<false>(ins,
                                IPOINT_BEFORE,
                                reinterpret_cast<AFUNPTR>(reinstrument_if_some_thread_started),
                                IARG_INST_PTR,
                                IARG_REG_VALUE, REG_STACK_PTR,
                                IARG_CONST_CONTEXT,
                                IARG_END);
        }
        else {
          static_assert(std::is_same<
                        decltype(reinstrument_if_some_thread_started), VOID (ADDRINT, ADDRINT, const CONTEXT*)
                        >::value, "invalid callback function type");

          ins_insert_call<false>(ins,
                                IPOINT_BEFORE,
                                reinterpret_cast<AFUNPTR>(reinstrument_if_some_thread_started),
                                IARG_INST_PTR,
                                IARG_ADDRINT, current_ins->next_address,
                                IARG_CONST_CONTEXT,
                                IARG_END);
        }
      }
    }
  }

  return;
}


template<typename T>
auto point_is_patchable(T patch_info_at_addr) -> bool
{
  return std::any_of(std::begin(patch_info_at_addr), std::end(patch_info_at_addr), [](typename T::const_reference patch_info)
  {
    auto patch_exec_point = std::get<0>(patch_info);
    auto exec_point       = std::get<0>(patch_exec_point);
    auto exec_addr        = std::get<0>(exec_point);
    auto exec_order       = std::get<1>(exec_point);

    return (exec_order >= execution_order_of_address[exec_addr]);
  });
}

static auto insert_ins_patch_info_callbacks (INS ins) -> void
{
  static auto register_is_patchable = true;
  static auto memory_is_patchable = true;
  static auto indirect_memory_is_patchable = true;

  if (register_is_patchable || memory_is_patchable || indirect_memory_is_patchable) {
    auto ins_addr = INS_Address(ins);

    if (execution_order_of_address.find(ins_addr) != execution_order_of_address.end()) {

      static_assert(std::is_same<
                    decltype(update_execution_order), VOID (ADDRINT, UINT32)
                    >::value, "invalid callback function type");

      ins_insert_call<false>(ins,                                               // instrumented instruction
                            IPOINT_BEFORE,                                     // instrumentation point
                            reinterpret_cast<AFUNPTR>(update_execution_order), // callback analysis function
                            IARG_INST_PTR,                                     // instruction address
                            IARG_THREAD_ID,                                    // thread id
                            IARG_END);

      if (register_is_patchable) {
        for (auto const& patch_reg_info : patched_register_at_address) {
          auto patch_exec_point = std::get<0>(patch_reg_info);

          auto patch_reg_value_info = std::get<1>(patch_reg_info);
          auto patch_reg = std::get<0>(patch_reg_value_info);

          auto exec_point = std::get<0>(patch_exec_point);
          auto exec_addr = std::get<0>(exec_point);
          auto exec_order = std::get<1>(exec_point);

          if ((exec_addr == ins_addr) && (exec_order >= execution_order_of_address[ins_addr])) {
            auto patch_point = std::get<1>(patch_exec_point);
            auto pin_patch_point = !patch_point ? IPOINT_BEFORE : IPOINT_AFTER;

            auto reg_size = REG_Size(patch_reg);

            ASSERTX(((reg_size == 1) || (reg_size == 2) || (reg_size == 4) || (reg_size == 8)) &&
                   "the needed to patch register has a unsupported length");

            if (INS_Valid(ins)) {

              static_assert(std::is_same<
                            decltype(patch_register), VOID (ADDRINT, bool, UINT32, PIN_REGISTER*, UINT32)
                            >::value, "invalid callback function type");

              ins_insert_call<false>(ins,                                       // instrumented instruction
                                    pin_patch_point,                           // instrumentation point
                                    reinterpret_cast<AFUNPTR>(patch_register), // callback analysis function
                                    IARG_INST_PTR,                             // instruction address
                                    IARG_BOOL, patch_point,                    // patch point (before or after)
                                    IARG_UINT32, patch_reg,
                                    IARG_REG_REFERENCE, patch_reg,             // patched register (reference)
                                    IARG_THREAD_ID,                            // thread id
                                    IARG_END);
            }
          }
        }
      }

      if (memory_is_patchable) {
        for (auto const& patch_mem_info : patched_memory_at_address) {

          auto patch_exec_point = std::get<0>(patch_mem_info);
          auto exec_point       = std::get<0>(patch_exec_point);
          auto exec_addr        = std::get<0>(exec_point);
          auto exec_order       = std::get<1>(exec_point);

          if ((exec_addr == ins_addr) && (exec_order >= execution_order_of_address[ins_addr])) {
            auto patch_point = std::get<1>(patch_exec_point);
            auto pin_patch_point = !patch_point ? IPOINT_BEFORE : IPOINT_AFTER;

            auto patch_mem_val = std::get<1>(patch_mem_info);
            auto patch_mem_addr = std::get<0>(patch_mem_val);

            static_assert(std::is_same<
                          decltype(patch_memory), VOID (ADDRINT, bool, ADDRINT, UINT32)
                          >::value, "invalid callback function type");

            ins_insert_call<false>(ins,                                     // instrumented instruction
                                  pin_patch_point,                         // instrumentation point
                                  reinterpret_cast<AFUNPTR>(patch_memory), // callback analysis function
                                  IARG_INST_PTR,                           // instruction address
                                  IARG_BOOL, patch_point,                  // patch point (before or after)
                                  IARG_ADDRINT, patch_mem_addr,
                                  IARG_THREAD_ID,                          // thread id
                                  IARG_END);
          }
        }
      }

      if (indirect_memory_is_patchable) {
        for (auto const& patch_indirect_mem_info : patched_indirect_memory_at_address) {

          auto patch_exec_point = std::get<0>(patch_indirect_mem_info);
          auto exec_point       = std::get<0>(patch_exec_point);
          auto exec_addr        = std::get<0>(exec_point);
          auto exec_order       = std::get<1>(exec_point);

          if ((exec_addr == ins_addr) && (exec_order >= execution_order_of_address[ins_addr])) {
            auto patch_point = std::get<1>(patch_exec_point);
            auto pin_patch_point = !patch_point ? IPOINT_BEFORE : IPOINT_AFTER;

            auto patch_value_info = std::get<1>(patch_indirect_mem_info);
            auto patch_indirect_reg = std::get<0>(patch_value_info);

           static_assert(std::is_same<
                         decltype(patch_indirect_memory), VOID (ADDRINT, bool, UINT32, ADDRINT, ADDRINT)
                         >::value, "invalid callback function type");

            ins_insert_call<false>(ins,
                                  pin_patch_point,
                                  reinterpret_cast<AFUNPTR>(patch_indirect_memory),
                                  IARG_INST_PTR,
                                  IARG_BOOL, patch_point,
                                  IARG_UINT32, patch_indirect_reg,
                                  IARG_REG_VALUE, patch_indirect_reg,
                                  IARG_THREAD_ID,
                                  IARG_END);
          }
        }
      }
    }

    register_is_patchable = point_is_patchable<decltype(patched_register_at_address)>(patched_register_at_address);

    memory_is_patchable = point_is_patchable<decltype(patched_memory_at_address)>(patched_memory_at_address);

    indirect_memory_is_patchable = point_is_patchable<decltype(patched_indirect_memory_at_address)>(patched_indirect_memory_at_address);
  }
  return;
}


auto proc_follow_process (CHILD_PROCESS child_proc, VOID* data) -> bool
{
  (void)data;

  auto child_argc = int{0};
  const char* const *child_argv;

  tfm::printfln("save trace before new process is created/forked...");
  cap_flush_trace();

  CHILD_PROCESS_GetCommandLine(child_proc, &child_argc, &child_argv);
  tfm::printf("new process is created/forked with: ");
  for (auto i = int{0}; i < child_argc; ++i) {
    tfm::printf("%s ", child_argv[i]);
  }
  tfm::printfln("");

  tfm::printfln("current pin command line for new process: %s");
  const char *pin_argv[] = { "./pin71313/ia32/bin/pinbin",
                             "-ifeellucky", "-follow_execv", "-t", "pintools/vtrace.pin_m32",
                             "-opt", "default.opt", "-out", "default.trace", "--" };
  CHILD_PROCESS_SetPinCommandLine(child_proc, 10, pin_argv);

//  tfm::printfln("%s", child_cmd.String());
  return true;
}



/*====================================================================================================================*/
/*                                                   exported functions                                               */
/*====================================================================================================================*/


static auto ins_mode_get_ins_info (INS ins, VOID* data) -> VOID
{
  (void)data;

  insert_ins_get_info_callbacks(ins);
  return;
}


static auto trace_mode_get_ins_info (TRACE trace, VOID* data) -> VOID
{
  (void)data;

  for (auto bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
    for (auto ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
      insert_ins_get_info_callbacks(ins);
    }
  }
  return;
}


static auto ins_mode_patch_ins_info (INS ins, VOID* data) -> VOID
{
  (void)data;
  insert_ins_patch_info_callbacks(ins);
  return;
}


static auto trace_mode_patch_ins_info (TRACE trace, VOID* data) -> VOID
{
  (void)data;

  for (auto bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
    for (auto ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
      insert_ins_patch_info_callbacks(ins);
    }
  }
  return;
}


static auto img_mode_get_ins_info (IMG img, VOID* data) -> VOID
{
  (void)data;

  for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
    for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn)) {

      RTN_Open(rtn);
      for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins)) {
        auto ins_addr = INS_Address(ins);

        if (cached_ins_at_addr.find(ins_addr) != std::end(cached_ins_at_addr)) continue;

        // update the code cache if a new instruction found.
        cached_ins_at_addr[ins_addr] = std::make_shared<instruction>(ins);

        if (!INS_IsDirectCall(ins)) continue;

        auto called_addr = INS_DirectBranchOrCallTargetAddress(ins);

        // if the current address is a full-skip, then add its called address as a auto-skip
        if (std::find(std::begin(full_skip_call_addresses),
                      std::end(full_skip_call_addresses), ins_addr) != std::end(full_skip_call_addresses)) {
          if (std::find(std::begin(auto_skip_call_addresses),
                        std::end(auto_skip_call_addresses), called_addr) != std::end(auto_skip_call_addresses)) {

            tfm::format(std::cerr, "add an auto-skip for 0x%x from the target of a full-skip at 0x%x %s\n",
                        called_addr, ins_addr, cached_ins_at_addr[ins_addr]->disassemble);
            auto_skip_call_addresses.push_back(called_addr);
          }
        }

        if (std::find(std::begin(auto_skip_call_addresses),
                      std::end(auto_skip_call_addresses), called_addr) != std::end(auto_skip_call_addresses)) {

          tfm::format(std::cerr, "add a full-skip at 0x%x  %s from an auto-skip at 0x%x\n",
                      ins_addr, cached_ins_at_addr[ins_addr]->disassemble, called_addr);
          full_skip_call_addresses.push_back(ins_addr);
        }
      }
      RTN_Close(rtn);
    }
  }

  tfm::format(std::cerr, "code cache size: %7d instructions processed\n", cached_ins_at_addr.size());

  return;
}

auto cap_initialize () -> void
{
  cached_ins_at_addr.clear();
  resume_address_of_thread.clear();
  trace.clear();

  start_address = 0x0; stop_address = 0x0;
  return;
}

auto cap_initialize_state () -> void
{
//  some_thread_is_started = false;
  some_thread_is_started = (start_address == 0x0);

  some_thread_is_not_suspended = true;
  return;
}


auto cap_set_start_address (ADDRINT address) -> void
{
  start_address = address;
  return;
}


auto cap_set_stop_address (ADDRINT address) -> void
{
  stop_address = address;
  return;
}


auto cap_add_full_skip_call_address (ADDRINT address) -> void
{
  full_skip_call_addresses.push_back(address);
  return;
}


auto cap_add_auto_skip_call_addresses (ADDRINT address) -> void
{
  auto_skip_call_addresses.push_back(address);
  return;
}


auto cap_set_loop_count (uint32_t count) -> void
{
  loop_count = count;
  return;
}


auto cap_set_trace_length (uint32_t trace_length) -> void
{
  max_trace_length = trace_length;
  return;
}


auto cap_add_patched_memory_value (ADDRINT ins_address, UINT32 exec_order, bool be_or_af,
                                   ADDRINT mem_address, UINT8 mem_size, ADDRINT mem_value) -> void
{
  auto exec_point         = exec_point_t(ins_address, exec_order);
  auto patched_exec_point = patch_point_t(exec_point, be_or_af);
  auto memory_value       = memory_patch_value_t(mem_address, mem_size, mem_value);
  
  patched_memory_at_address.push_back(std::make_pair(patched_exec_point, memory_value));
  execution_order_of_address[ins_address] = 0;

  return;
}


auto cap_add_patched_register_value (ADDRINT ins_address, UINT32 exec_order, bool be_or_af,
                                     REG reg, UINT8 lo_pos, UINT8 hi_pos, ADDRINT reg_value) -> void
{
  auto exec_point             = exec_point_t(ins_address, exec_order);
  auto patched_exec_point     = patch_point_t(exec_point, be_or_af);
  auto patched_register_value = register_patch_value_t(reg, lo_pos, hi_pos, reg_value);

  patched_register_at_address.push_back(std::make_pair(patched_exec_point, patched_register_value));
  execution_order_of_address[ins_address] = 0;

  return;
}

auto cap_add_patched_indirect_memory_value (ADDRINT ins_address, UINT32 exec_order, bool be_or_af,
                                            REG reg, UINT8 mem_size, ADDRINT mem_value) -> void
{
  auto exec_point = exec_point_t(ins_address, exec_order);
  auto patched_exec_point = patch_point_t(exec_point, be_or_af);
  auto patched_indirect_memory_value = indirect_memory_patch_value_t(reg, mem_size, mem_value);

  patched_indirect_memory_at_address.push_back(std::make_pair(patched_exec_point, patched_indirect_memory_value));
  execution_order_of_address[ins_address] = 0;

  return;
}

auto cap_verify_parameters () -> void
{
  tfm::format(std::cerr, "start address 0x%x\n", start_address);
  tfm::format(std::cerr, "stop address 0x%x\n", stop_address);
  return;
}


ins_instrumentation_t cap_ins_mode_get_ins_info          = ins_mode_get_ins_info;
ins_instrumentation_t cap_patch_instrunction_information = ins_mode_patch_ins_info;
trace_instrumentation_t cap_trace_mode_get_ins_info      = trace_mode_get_ins_info;
trace_instrumentation_t cap_trace_mode_patch_ins_info    = trace_mode_patch_ins_info;
img_instrumentation_t cap_img_mode_get_ins_info          = img_mode_get_ins_info;
