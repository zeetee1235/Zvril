#pragma once
#include "zvril/elf/image.h"
#include <set>
namespace llvm { class Module; }
namespace zvril { void emit_image(llvm::Module&, const Image&, std::set<std::string>&); }
