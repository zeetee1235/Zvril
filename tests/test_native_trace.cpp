#include "zvril/native_trace.h"
#include <cassert>
using llvm::json::Array;
using llvm::json::Object;
using llvm::json::Value;
Object trace(bool native) {
  Array gpr;
  for (unsigned i = 0; i < 17; i++) gpr.push_back("0x0");
  Object row{{"pc", "0x1234"}, {"gpr", std::move(gpr)}, {"flags", "0x202"}};
  if (!native) row["flags_valid"] = "0xcd5";
  return Object{{"records", Array{std::move(row)}}, {"complete", true},
                {"truncated", false}, {"error", ""}};
}
int main() {
  auto a = trace(true), b = trace(false);
  auto result = zvril::compare_instruction_traces(a, b);
  assert(result.getString("status") == "PASS");
  (*b.getArray("records"))[0].getAsObject()->operator[]("flags") = "0x0";
  assert(zvril::compare_instruction_traces(a, b).getString("status") == "PASS");
  (*b.getArray("records"))[0].getAsObject()->operator[]("flags") = "0x1";
  result = zvril::compare_instruction_traces(a, b);
  assert(result.getString("field") == "defined_flags");
  b = trace(false);
  (*(*b.getArray("records"))[0].getAsObject()->getArray("gpr"))[7] = "0x42";
  result = zvril::compare_instruction_traces(a, b);
  assert(result.getString("field") == "gpr[7]");
  assert(result.getInteger("instruction_index") == 0);
  b = trace(false);
  (*b.getArray("records"))[0].getAsObject()->operator[]("pc") = "0x1235";
  assert(zvril::compare_instruction_traces(a, b).getString("field") == "pc");
  b = trace(false); b.getArray("records")->clear();
  assert(zvril::compare_instruction_traces(a, b).getString("field") == "instruction_count");
  b = trace(false); b["truncated"] = true;
  assert(zvril::compare_instruction_traces(a, b).getString("status") == "UNKNOWN");
  b = trace(false); (*b.getArray("records"))[0].getAsObject()->erase("flags_valid");
  bool rejected = false;
  try { zvril::compare_instruction_traces(a, b); }
  catch (const zvril::Error &e) { rejected = e.code == "E_TRACE_PROTOCOL"; }
  assert(rejected);
}
