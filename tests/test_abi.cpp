#include "zvril/abi.h"
#include <cassert>
#include <llvm/Support/Error.h>
#include <string>
#include <vector>

int main() {
  const std::vector<std::string> bad{
      R"({"size":8,"alignment":8,"fields":[]})",
      R"({"size":8,"alignment":8,"fields":42})",
      R"({"size":8,"alignment":8,"fields":[{"offset":-1,"type":"u64"}]})",
      R"({"size":8,"alignment":8,"fields":[{"offset":1,"type":"u64"}]})",
      R"({"size":8,"alignment":8,"fields":[{"offset":0,"type":"u64"},{"offset":4,"type":"u32"}]})",
      R"({"size":8,"alignment":8,"fields":[{"offset":0,"type":"void"}]})",
      R"({"size":8,"alignment":8,"fields":[{"offset":0,"type":"u64","typo":true}]})",
      R"({"size":8,"alignment":8,"classes":["INTEGER"],"defined_bytes":[]})",
      R"({"size":8,"alignment":8,"classes":["INTEGER"],"pointer_offsets":{}})",
      R"({"size":8,"alignment":8,"classes":["NO_CLASS"]})",
      R"({"size":8,"alignment":8,"fields":[{"offset":0,"type":"f64"}],"classes":["INTEGER"]})",
      R"({"size":16,"alignment":8,"classes":["INTEGER","INTEGER"],"pointer_offsets":[0,4]})"};
  for (const auto &layout : bad) {
    auto document = llvm::json::parse("{\"return\":\"void\",\"arguments\":[{\"aggregate\":" + layout + "}]}");
    assert(document);
    bool rejected = false;
    try { zvril::parse_abi(*document->getAsObject()); }
    catch (const zvril::Error &e) { rejected = e.code == "E_ABI_UNKNOWN"; }
    assert(rejected);
  }
  std::string nested = "\"u64\"";
  for (unsigned i = 0; i < 10; i++)
    nested = "{\"aggregate\":{\"size\":8,\"alignment\":8,\"fields\":[{\"offset\":0,\"type\":" + nested + "}]}}";
  auto too_deep = llvm::json::parse("{\"return\":\"void\",\"arguments\":[" + nested + "]}");
  assert(too_deep);
  bool rejected = false;
  try { zvril::parse_abi(*too_deep->getAsObject()); }
  catch (const zvril::Error &e) { rejected = e.code == "E_ABI_UNKNOWN"; }
  assert(rejected);
  auto aligned = llvm::json::parse(R"({"return":{"aggregate":{"size":16,"alignment":16,"fields":[{"offset":0,"type":"u64"}]}},"arguments":[]})");
  assert(aligned);
  auto layout = zvril::parse_abi(*aligned->getAsObject());
  assert(layout.result.classes == std::vector<zvril::AbiClass>({zvril::AbiClass::Integer, zvril::AbiClass::None}));
  assert(layout.result.defined[7] && !layout.result.defined[8]);
}
