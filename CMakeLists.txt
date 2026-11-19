cmake_minimum_required(VERSION 3.21)
project(Zvril VERSION 0.0.1 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
# Ubuntu installs LLVM 22 under /usr/lib/llvm-22 instead of the default CMake
# search path. Prefer that pinned toolchain when the caller did not select one.
if(NOT LLVM_DIR AND EXISTS "/usr/lib/llvm-22/lib/cmake/llvm/LLVMConfig.cmake")
  set(LLVM_DIR "/usr/lib/llvm-22/lib/cmake/llvm")
endif()
find_package(LLVM REQUIRED CONFIG)
if(NOT LLVM_VERSION_MAJOR EQUAL 22)
  message(FATAL_ERROR "This baseline is tested with LLVM 22; select LLVM_DIR explicitly")
endif()
message(STATUS "Zvril analysis dependency: LLVM ${LLVM_PACKAGE_VERSION}")
include(CTest)
option(ZVRIL_REMILL "Build the pinned Remill x86 backend" ON)
if(ZVRIL_REMILL)
  include(cmake/Remill.cmake)
endif()

option(ZVRIL_SANITIZERS "Enable address and undefined behavior sanitizers" OFF)
option(ZVRIL_FUZZING "Build the Clang libFuzzer ELF parser harness" OFF)
add_library(zvril_elf src/elf/image.cpp src/elf/discovery.cpp src/elf/versions.cpp)
target_include_directories(zvril_elf PUBLIC include)
target_include_directories(zvril_elf SYSTEM PRIVATE ${LLVM_INCLUDE_DIRS})
llvm_map_components_to_libnames(ZVRIL_ELF_LLVM_LIBS DebugInfoDWARF Object Support)
target_link_libraries(zvril_elf PUBLIC ${ZVRIL_ELF_LLVM_LIBS})
target_compile_options(zvril_elf PRIVATE -Wall -Wextra -Wpedantic)
add_executable(zvril src/cli/main.cpp src/cli/batch.cpp src/semantics/lift.cpp src/semantics/discover.cpp)
target_include_directories(zvril SYSTEM PRIVATE ${LLVM_INCLUDE_DIRS})
target_compile_definitions(zvril PRIVATE ZVRIL_VERSION="${PROJECT_VERSION}")
target_compile_options(zvril PRIVATE -Wall -Wextra -Wpedantic)
llvm_map_components_to_libnames(ZVRIL_LLVM_LIBS Support)
target_link_libraries(zvril PRIVATE zvril_elf ${ZVRIL_LLVM_LIBS})
if(ZVRIL_REMILL)
  add_custom_command(OUTPUT "${CMAKE_BINARY_DIR}/generated/demo_fixture.h"
    COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_BINARY_DIR}/generated"
    COMMAND ${CMAKE_C_COMPILER} -shared -fPIC -O1 -fno-stack-protector -nostdlib
      "${CMAKE_CURRENT_SOURCE_DIR}/examples/demo.c" -o "${CMAKE_BINARY_DIR}/generated/demo.so"
    COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/tools/embed.py"
      "${CMAKE_BINARY_DIR}/generated/demo.so" "${CMAKE_BINARY_DIR}/generated/demo_fixture.h"
    DEPENDS examples/demo.c tools/embed.py VERBATIM)
  target_sources(zvril PRIVATE "${CMAKE_BINARY_DIR}/generated/demo_fixture.h")
  target_include_directories(zvril PRIVATE "${CMAKE_BINARY_DIR}/generated")
  target_sources(zvril PRIVATE src/abi/sysv.cpp src/semantics/image_ir.cpp src/semantics/indirect.cpp src/verify/verify.cpp src/verify/sandbox.cpp src/verify/native_trace.cpp src/verify/cpu_profile.cpp src/process/execute.cpp src/process/files.cpp src/process/signals.cpp src/runtime/runtime.c)
  llvm_map_components_to_libnames(ZVRIL_JIT_LIBS MCJIT ExecutionEngine RuntimeDyld native)
  target_link_libraries(zvril PRIVATE ${ZVRIL_JIT_LIBS})
  target_compile_definitions(zvril PRIVATE ZVRIL_HAS_REMILL=1
    ZVRIL_SEMANTICS_FILE="${ZVRIL_SEMANTICS}"
    ZVRIL_REMILL_REVISION="66c488c9911fd9b368e4d0c9647d74239f8bba8b")
  target_link_libraries(zvril PRIVATE zvril_remill)
  add_dependencies(zvril zvril_semantics)
endif()
if(ZVRIL_SANITIZERS)
  target_compile_definitions(zvril PRIVATE ZVRIL_SANITIZED=1)
  foreach(target zvril zvril_elf)
    target_compile_options(${target} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
  endforeach()
  if(ZVRIL_REMILL)
    target_compile_options(zvril_remill PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
  endif()
  target_link_options(zvril PRIVATE -fsanitize=address,undefined)
endif()

if(BUILD_TESTING)
  add_executable(zvril_runtime_test tests/test_runtime.c src/runtime/runtime.c)
  target_include_directories(zvril_runtime_test PRIVATE include)
  target_compile_options(zvril_runtime_test PRIVATE -UNDEBUG)
  if(ZVRIL_SANITIZERS)
    target_compile_options(zvril_runtime_test PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(zvril_runtime_test PRIVATE -fsanitize=address,undefined)
  endif()
  add_test(NAME runtime_pages_transactions COMMAND zvril_runtime_test)
  find_package(Python3 REQUIRED COMPONENTS Interpreter)
  add_test(NAME regression_manifest_contract COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_tools.py ${CMAKE_CURRENT_SOURCE_DIR})
  add_test(NAME cli_and_elf_regression
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_cli.py
      $<TARGET_FILE:zvril> ${CMAKE_C_COMPILER} ${CMAKE_CURRENT_SOURCE_DIR})
  set_tests_properties(cli_and_elf_regression PROPERTIES TIMEOUT 90)
  if(ZVRIL_REMILL)
    add_executable(zvril_trace_test tests/test_native_trace.cpp src/verify/native_trace.cpp)
    target_link_libraries(zvril_trace_test PRIVATE zvril_elf)
    target_include_directories(zvril_trace_test SYSTEM PRIVATE ${LLVM_INCLUDE_DIRS})
    target_compile_options(zvril_trace_test PRIVATE -UNDEBUG)
    if(ZVRIL_SANITIZERS)
      target_compile_options(zvril_trace_test PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
      target_link_options(zvril_trace_test PRIVATE -fsanitize=address,undefined)
    endif()
    add_test(NAME native_trace_comparator COMMAND zvril_trace_test)
    add_executable(zvril_abi_test tests/test_abi.cpp src/abi/sysv.cpp)
    llvm_map_components_to_libnames(ZVRIL_ABI_TEST_LIBS Core Support)
    target_link_libraries(zvril_abi_test PRIVATE zvril_elf ${ZVRIL_ABI_TEST_LIBS})
    target_include_directories(zvril_abi_test SYSTEM PRIVATE ${LLVM_INCLUDE_DIRS})
    target_compile_options(zvril_abi_test PRIVATE -UNDEBUG)
    if(ZVRIL_SANITIZERS)
      target_compile_options(zvril_abi_test PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
      target_link_options(zvril_abi_test PRIVATE -fsanitize=address,undefined)
    endif()
    add_test(NAME abi_layout_input_validation COMMAND zvril_abi_test)
    add_test(NAME vendor_source_integrity COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tools/check_sources.py)
    add_test(NAME dynamic_linux_process_execution
      COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_process.py
        $<TARGET_FILE:zvril> ${CMAKE_C_COMPILER} ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_BINARY_DIR}/test-results/process.json)
    set_tests_properties(dynamic_linux_process_execution PROPERTIES TIMEOUT 240)
    add_test(NAME linux_process_files_and_signals
      COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_process_kernel.py
        $<TARGET_FILE:zvril> ${CMAKE_C_COMPILER} ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_BINARY_DIR}/test-results/process-kernel.json)
    set_tests_properties(linux_process_files_and_signals PROPERTIES TIMEOUT 240)
    add_test(NAME dynamic_loader_glibc_process
      COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_process_dynamic.py
        $<TARGET_FILE:zvril> ${CMAKE_C_COMPILER} ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_BINARY_DIR}/test-results/process-dynamic.json)
    set_tests_properties(dynamic_loader_glibc_process PROPERTIES TIMEOUT 900)
    add_test(NAME cpp_exception_unwind_process
      COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_process_exceptions.py
        $<TARGET_FILE:zvril> ${CMAKE_C_COMPILER} ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_BINARY_DIR}/test-results/process-exceptions.json)
    set_tests_properties(cpp_exception_unwind_process PROPERTIES TIMEOUT 1500)
    add_test(NAME glibc_pthread_and_dlopen
      COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_process_extended.py
        $<TARGET_FILE:zvril> ${CMAKE_C_COMPILER} ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_BINARY_DIR}/test-results/process-extended.json)
    set_tests_properties(glibc_pthread_and_dlopen PROPERTIES TIMEOUT 1500)
    add_test(NAME x87_long_double_process
      COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_process_x87.py
        $<TARGET_FILE:zvril> ${CMAKE_C_COMPILER} ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_BINARY_DIR}/test-results/process-x87.json)
    set_tests_properties(x87_long_double_process PROPERTIES TIMEOUT 600)
    add_test(NAME glibc_filesystem_coreutils
      COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_process_filesystem.py
        $<TARGET_FILE:zvril> ${CMAKE_C_COMPILER} ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_BINARY_DIR}/test-results/process-filesystem.json)
    set_tests_properties(glibc_filesystem_coreutils PROPERTIES TIMEOUT 1500)
    add_test(NAME remill_end_to_end
      COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_lifting.py
        $<TARGET_FILE:zvril> ${CMAKE_C_COMPILER} ${ZVRIL_CLANG} ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_BINARY_DIR}/test-results/lifting.json)
    set_tests_properties(remill_end_to_end PROPERTIES TIMEOUT 240)
    add_test(NAME rep_string_state_and_faults
      COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_strings.py
        $<TARGET_FILE:zvril> ${CMAKE_C_COMPILER} ${ZVRIL_CLANG} ${CMAKE_CURRENT_SOURCE_DIR})
    set_tests_properties(rep_string_state_and_faults PROPERTIES TIMEOUT 240)
    add_test(NAME immutable_function_pointer_tables
      COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_indirect_tables.py
        $<TARGET_FILE:zvril> ${CMAKE_C_COMPILER} ${ZVRIL_CLANG} ${CMAKE_CURRENT_SOURCE_DIR})
    set_tests_properties(immutable_function_pointer_tables PROPERTIES TIMEOUT 120)
    add_test(NAME integer_division_state_and_faults
      COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_division.py
        $<TARGET_FILE:zvril> ${CMAKE_C_COMPILER} ${ZVRIL_CLANG} ${CMAKE_CURRENT_SOURCE_DIR})
    set_tests_properties(integer_division_state_and_faults PROPERTIES TIMEOUT 180)
    add_test(NAME scalar_integer_abi_widths
      COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_narrow_abi.py
        $<TARGET_FILE:zvril> ${CMAKE_C_COMPILER} ${ZVRIL_CLANG} ${CMAKE_CURRENT_SOURCE_DIR})
    set_tests_properties(scalar_integer_abi_widths PROPERTIES TIMEOUT 180)
    set(ZVRIL_VERSION_TEST_ARGS)
    if(ZVRIL_SANITIZERS)
      set(ZVRIL_VERSION_TEST_ARGS --static)
    endif()
    add_test(NAME relocations_and_symbol_versions
      COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_relocations_versions.py
        $<TARGET_FILE:zvril> ${CMAKE_C_COMPILER} ${ZVRIL_CLANG} ${CMAKE_CURRENT_SOURCE_DIR} ${ZVRIL_VERSION_TEST_ARGS})
    set_tests_properties(relocations_and_symbol_versions PROPERTIES TIMEOUT 180)
    if(NOT ZVRIL_SANITIZERS)
      add_executable(zvril_sandbox_test tests/test_sandbox.cpp src/verify/sandbox.cpp)
      target_link_libraries(zvril_sandbox_test PRIVATE zvril_elf)
      target_include_directories(zvril_sandbox_test SYSTEM PRIVATE ${LLVM_INCLUDE_DIRS})
      target_compile_options(zvril_sandbox_test PRIVATE -UNDEBUG)
      add_test(NAME execution_sandbox_boundaries COMMAND zvril_sandbox_test $<TARGET_FILE:zvril_sandbox_test>)
      set_tests_properties(execution_sandbox_boundaries PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 10)
      add_test(NAME sandboxed_native_verification
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_verify.py
          $<TARGET_FILE:zvril> ${CMAKE_C_COMPILER} ${CMAKE_CURRENT_SOURCE_DIR} ${ZVRIL_CLANG})
      set_tests_properties(sandboxed_native_verification PROPERTIES TIMEOUT 180)
      add_test(NAME compiler_indirect_and_abi
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_expansion.py
          $<TARGET_FILE:zvril> ${CMAKE_C_COMPILER} ${ZVRIL_CLANG} ${CMAKE_CURRENT_SOURCE_DIR})
      set_tests_properties(compiler_indirect_and_abi PROPERTIES TIMEOUT 180)
      add_test(NAME sysv_aggregate_contracts
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_aggregate.py
          $<TARGET_FILE:zvril> ${CMAKE_C_COMPILER} ${ZVRIL_CLANG} ${CMAKE_CURRENT_SOURCE_DIR})
      set_tests_properties(sysv_aggregate_contracts PROPERTIES TIMEOUT 180)
    endif()
  endif()
endif()
if(ZVRIL_FUZZING)
  if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR NOT ZVRIL_SANITIZERS)
    message(FATAL_ERROR "ZVRIL_FUZZING requires Clang and ZVRIL_SANITIZERS=ON")
  endif()
  target_compile_options(zvril_elf PRIVATE -fsanitize=fuzzer-no-link)
  add_executable(zvril_fuzz_elf tests/fuzz_elf.cpp)
  target_link_libraries(zvril_fuzz_elf PRIVATE zvril_elf)
  target_compile_options(zvril_fuzz_elf PRIVATE -fsanitize=fuzzer,address,undefined)
  target_link_options(zvril_fuzz_elf PRIVATE -fsanitize=fuzzer,address,undefined)
endif()
install(TARGETS zvril RUNTIME DESTINATION bin)
install(DIRECTORY docs schemas DESTINATION share/zvril)
install(FILES README.md DESTINATION share/zvril)
install(FILES include/zvril/runtime.h DESTINATION include/zvril)
if(ZVRIL_REMILL)
  install(FILES "${ZVRIL_SEMANTICS}" DESTINATION share/zvril/semantics)
  install(FILES "${CMAKE_BINARY_DIR}/semantics/amd64_avx.bc" "${CMAKE_BINARY_DIR}/semantics/amd64_avx512.bc" DESTINATION share/zvril/semantics)
  install(FILES "${ZVRIL_RUNTIME_BC}" DESTINATION share/zvril/semantics)
  foreach(dependency remill xed mbuild)
    install(FILES "third_party/src/${dependency}/LICENSE" DESTINATION share/zvril/licenses/${dependency})
  endforeach()
  install(FILES third_party/src/glog/COPYING DESTINATION share/zvril/licenses/glog)
  install(FILES third_party/src/gflags/COPYING.txt DESTINATION share/zvril/licenses/gflags)
  install(FILES third_party/licenses/llvm/LICENSE.TXT DESTINATION share/zvril/licenses/llvm)
  install(FILES third_party/sources.lock.json DESTINATION share/zvril)
  install(FILES third_party/corpus.lock.json DESTINATION share/zvril)
  file(GLOB ZVRIL_CORPUS_LICENSES "${CMAKE_CURRENT_SOURCE_DIR}/third_party/corpus/*/LICENSE")
  foreach(license ${ZVRIL_CORPUS_LICENSES})
    get_filename_component(parent "${license}" DIRECTORY)
    get_filename_component(project "${parent}" NAME)
    install(FILES "${license}" DESTINATION "share/zvril/licenses/validation-corpus/${project}")
  endforeach()
endif()
