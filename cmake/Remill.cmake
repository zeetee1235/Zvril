# Build only the x86/XED portion of the pinned Remill source snapshot.
# The upstream source and licenses remain in third_party/src, unchanged.
find_package(Python3 REQUIRED COMPONENTS Interpreter)
set(ZVRIL_VENDOR "${PROJECT_SOURCE_DIR}/third_party/src")
set(ZVRIL_REMILL_SOURCE "${ZVRIL_VENDOR}/remill")
set(ZVRIL_DEPS "${CMAKE_BINARY_DIR}/deps")
set(ZVRIL_XED_KIT "${ZVRIL_DEPS}/xed-kit")
set(ZVRIL_XED_LIBRARY "${ZVRIL_XED_KIT}/lib/libxed.a")
file(GLOB_RECURSE ZVRIL_XED_INPUTS CONFIGURE_DEPENDS "${ZVRIL_VENDOR}/xed/*" "${ZVRIL_VENDOR}/mbuild/*")
add_custom_command(OUTPUT "${ZVRIL_XED_LIBRARY}"
  COMMAND ${Python3_EXECUTABLE} "${ZVRIL_VENDOR}/xed/mfile.py"
    "--build-dir=${ZVRIL_DEPS}/xed-obj" "--install-dir=${ZVRIL_XED_KIT}"
    --no-encoder --no-werror --extra-flags=-fPIC -j 4 install
  WORKING_DIRECTORY "${ZVRIL_VENDOR}/xed"
  DEPENDS ${ZVRIL_XED_INPUTS}
  COMMENT "Building pinned Intel XED decoder (offline)" VERBATIM)
add_custom_target(zvril_xed DEPENDS "${ZVRIL_XED_LIBRARY}")

set(REGISTER_BUILD_DIR OFF CACHE BOOL "" FORCE)
set(REGISTER_INSTALL_PREFIX OFF CACHE BOOL "" FORCE)
set(GFLAGS_BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(GFLAGS_BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(GFLAGS_BUILD_STATIC_LIBS ON CACHE BOOL "" FORCE)
set(GFLAGS_USE_TARGET_NAMESPACE ON CACHE BOOL "" FORCE)
add_subdirectory("${ZVRIL_VENDOR}/gflags" "${ZVRIL_DEPS}/gflags-local" EXCLUDE_FROM_ALL)
set(_zvril_testing "${BUILD_TESTING}")
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(WITH_GFLAGS OFF CACHE BOOL "" FORCE)
set(WITH_GTEST OFF CACHE BOOL "" FORCE)
set(WITH_UNWIND OFF CACHE BOOL "" FORCE)
add_subdirectory("${ZVRIL_VENDOR}/glog" "${ZVRIL_DEPS}/glog-local" EXCLUDE_FROM_ALL)
set(BUILD_TESTING "${_zvril_testing}" CACHE BOOL "" FORCE)

# Compatibility patches are applied to a build copy, never to upstream files.
set(ZVRIL_REMILL_PATCHED "${ZVRIL_DEPS}/remill")
execute_process(COMMAND ${Python3_EXECUTABLE} "${PROJECT_SOURCE_DIR}/tools/prepare_remill.py"
  "${ZVRIL_REMILL_SOURCE}" "${ZVRIL_REMILL_PATCHED}" COMMAND_ERROR_IS_FATAL ANY)
file(GLOB_RECURSE ZVRIL_REMILL_HEADERS CONFIGURE_DEPENDS "${ZVRIL_REMILL_SOURCE}/include/*")
add_library(zvril_remill STATIC
  "${ZVRIL_REMILL_PATCHED}/lib/Arch/Arch.cpp"
  "${ZVRIL_REMILL_PATCHED}/lib/BC/Util.cpp"
  "${ZVRIL_REMILL_SOURCE}/lib/Arch/Context.cpp"
  "${ZVRIL_REMILL_SOURCE}/lib/Arch/Instruction.cpp"
  "${ZVRIL_REMILL_SOURCE}/lib/Arch/Name.cpp"
  "${ZVRIL_REMILL_SOURCE}/lib/Arch/X86/Arch.cpp"
  "${ZVRIL_REMILL_SOURCE}/lib/Arch/X86/Base.cpp"
  "${ZVRIL_REMILL_SOURCE}/lib/BC/ABI.cpp"
  "${ZVRIL_REMILL_SOURCE}/lib/BC/Annotate.cpp"
  "${ZVRIL_REMILL_SOURCE}/lib/BC/InstructionLifter.cpp"
  "${ZVRIL_REMILL_SOURCE}/lib/BC/IntrinsicTable.cpp"
  "${ZVRIL_REMILL_SOURCE}/lib/OS/OS.cpp"
  "${ZVRIL_REMILL_SOURCE}/lib/OS/FileSystem.cpp")
add_dependencies(zvril_remill zvril_xed)
target_include_directories(zvril_remill SYSTEM PUBLIC "${ZVRIL_REMILL_SOURCE}/include" ${LLVM_INCLUDE_DIRS})
target_include_directories(zvril_remill SYSTEM PRIVATE "${ZVRIL_XED_KIT}/include")
target_compile_options(zvril_remill PRIVATE -Wno-unknown-pragmas -Wno-deprecated-declarations)
foreach(arch X86 AARCH32 AARCH64 SPARC32 SPARC64 PPC64_32ADDR)
  target_compile_definitions(zvril_remill PRIVATE REMILL_BUILD_SEMANTICS_DIR_${arch}="${CMAKE_BINARY_DIR}/semantics")
endforeach()
target_compile_definitions(zvril_remill PRIVATE REMILL_INSTALL_SEMANTICS_DIR="${CMAKE_INSTALL_PREFIX}/share/zvril/semantics")
llvm_map_components_to_libnames(ZVRIL_LIFTER_LLVM_LIBS Core Support IRReader BitReader BitWriter
  Passes TransformUtils ScalarOpts InstCombine Analysis TargetParser)
target_link_libraries(zvril_remill PUBLIC glog::glog gflags::gflags ${ZVRIL_LIFTER_LLVM_LIBS} "${ZVRIL_XED_LIBRARY}")

find_program(ZVRIL_CLANG NAMES clang++-22 clang++ REQUIRED)
find_program(ZVRIL_LLVM_LINK NAMES llvm-link-22 llvm-link REQUIRED)
foreach(tool ZVRIL_CLANG ZVRIL_LLVM_LINK)
  execute_process(COMMAND "${${tool}}" --version OUTPUT_VARIABLE _tool_version COMMAND_ERROR_IS_FATAL ANY)
  if(NOT _tool_version MATCHES "version ${LLVM_VERSION_MAJOR}\\.")
    message(FATAL_ERROR "${tool} must match LLVM ${LLVM_VERSION_MAJOR}: ${${tool}}")
  endif()
endforeach()
file(READ "${ZVRIL_REMILL_SOURCE}/LICENSE" ZVRIL_REMILL_LICENSE_TEXT)
configure_file("${PROJECT_SOURCE_DIR}/cmake/remill_license.h.in" "${CMAKE_BINARY_DIR}/generated/remill_license.h" @ONLY)
set(ZVRIL_SEMANTICS "${CMAKE_BINARY_DIR}/semantics/amd64.bc")
set(_bc_flags -std=c++17 -emit-llvm -c -ffreestanding -fno-builtin -fno-exceptions -fno-rtti
  -fno-vectorize -fno-slp-vectorize -mlong-double-80 -Wno-everything -nostdinc++
  -isystem "${ZVRIL_REMILL_SOURCE}/include/remill/Arch/Runtime/sysroot"
  -I "${ZVRIL_REMILL_SOURCE}/include" -I "${ZVRIL_REMILL_SOURCE}"
  -DADDRESS_SIZE_BITS=64 -DHAS_FEATURE_AVX=0 -DHAS_FEATURE_AVX512=0)
file(GLOB ZVRIL_SEMANTICS_INPUTS CONFIGURE_DEPENDS "${ZVRIL_REMILL_SOURCE}/lib/Arch/X86/Semantics/*.cpp")
set(_bc_objects)
foreach(unit Instructions BasicBlock Intrinsics)
  if(unit STREQUAL "Intrinsics")
    set(_src "${ZVRIL_REMILL_SOURCE}/lib/Arch/Runtime/Intrinsics.cpp")
  else()
    set(_src "${ZVRIL_REMILL_SOURCE}/lib/Arch/X86/Runtime/${unit}.cpp")
  endif()
  set(_bc "${CMAKE_BINARY_DIR}/semantics/${unit}.bc")
  add_custom_command(OUTPUT "${_bc}"
    COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_BINARY_DIR}/semantics"
    COMMAND "${ZVRIL_CLANG}" ${_bc_flags} -O1 "${_src}" -o "${_bc}"
    DEPENDS "${_src}" ${ZVRIL_REMILL_HEADERS} ${ZVRIL_SEMANTICS_INPUTS} VERBATIM)
  list(APPEND _bc_objects "${_bc}")
endforeach()
add_custom_command(OUTPUT "${ZVRIL_SEMANTICS}"
  COMMAND "${ZVRIL_LLVM_LINK}" ${_bc_objects} -o "${ZVRIL_SEMANTICS}"
  DEPENDS ${_bc_objects} VERBATIM)
set(ZVRIL_RUNTIME_BC "${CMAKE_BINARY_DIR}/semantics/runtime.bc")
add_custom_command(OUTPUT "${ZVRIL_RUNTIME_BC}"
  COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_BINARY_DIR}/semantics"
  COMMAND "${ZVRIL_CLANG}" -x c -std=c11 -target x86_64-pc-linux-gnu -emit-llvm -c -O1 -fno-builtin
    -I "${PROJECT_SOURCE_DIR}/include" "${PROJECT_SOURCE_DIR}/src/runtime/runtime.c" -o "${ZVRIL_RUNTIME_BC}"
  DEPENDS "${PROJECT_SOURCE_DIR}/src/runtime/runtime.c" "${PROJECT_SOURCE_DIR}/include/zvril/runtime.h" VERBATIM)
set(_all_semantics "${ZVRIL_SEMANTICS}" "${ZVRIL_RUNTIME_BC}")
set(_avx_flags ${_bc_flags})
list(REMOVE_ITEM _avx_flags -DHAS_FEATURE_AVX=0 -DHAS_FEATURE_AVX512=0)
foreach(isa amd64_avx amd64_avx512)
  if(isa STREQUAL "amd64_avx512")
    set(_avx512 1)
  else()
    set(_avx512 0)
  endif()
  set(_instructions "${CMAKE_BINARY_DIR}/semantics/${isa}.instructions.bc")
  set(_sem "${CMAKE_BINARY_DIR}/semantics/${isa}.bc")
  add_custom_command(OUTPUT "${_instructions}"
    COMMAND "${ZVRIL_CLANG}" ${_avx_flags} -DHAS_FEATURE_AVX=1 -DHAS_FEATURE_AVX512=${_avx512} -O1
      "${ZVRIL_REMILL_SOURCE}/lib/Arch/X86/Runtime/Instructions.cpp" -o "${_instructions}"
    DEPENDS ${ZVRIL_REMILL_HEADERS} ${ZVRIL_SEMANTICS_INPUTS} VERBATIM)
  add_custom_command(OUTPUT "${_sem}"
    COMMAND "${ZVRIL_LLVM_LINK}" "${_instructions}" "${CMAKE_BINARY_DIR}/semantics/BasicBlock.bc"
      "${CMAKE_BINARY_DIR}/semantics/Intrinsics.bc" -o "${_sem}"
    DEPENDS "${_instructions}" "${CMAKE_BINARY_DIR}/semantics/BasicBlock.bc" "${CMAKE_BINARY_DIR}/semantics/Intrinsics.bc" VERBATIM)
  list(APPEND _all_semantics "${_sem}")
endforeach()
add_custom_target(zvril_semantics DEPENDS ${_all_semantics})
