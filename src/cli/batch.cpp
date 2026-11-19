#include "zvril/batch.h"
#include <algorithm>
#include <chrono>
#include <fstream>
#include <llvm/Support/FormatVariadic.h>
#include <map>
#include <signal.h>
#include <sstream>
#include <sys/resource.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
namespace zvril {
BatchResult
batch(const Image &image, const std::filesystem::path &output, unsigned jobs,
      std::uint64_t timeout, const std::vector<std::string> &selection,
      std::function<int(const Function &, const std::filesystem::path &,
                        llvm::json::Object &)>
          action) {
  using llvm::json::Array;
  using llvm::json::Object;
  using llvm::json::Value;
  std::map<std::uint64_t, Function> unique;
  for (const auto &f : image.functions) {
    if (!selection.empty() && std::find(selection.begin(), selection.end(),
                                        f.name) == selection.end())
      continue;
    auto found = unique.find(f.address);
    if (found == unique.end() || (!found->second.size && f.size))
      unique[f.address] = f;
  }
  if (!selection.empty())
    for (const auto &s : selection)
      if (std::none_of(image.functions.begin(), image.functions.end(),
                       [&](const auto &f) { return f.name == s; }))
        throw Error("E_FUNCTION_NOT_FOUND", "Batch selection not found: " + s,
                    1);
  std::vector<Function> functions;
  for (const auto &[_, f] : unique)
    functions.push_back(f);
  struct Active {
    std::size_t index;
    std::chrono::steady_clock::time_point start;
    std::filesystem::path output;
  };
  std::map<pid_t, Active> active;
  std::map<std::size_t, Object> records;
  std::size_t next = 0;
  BatchResult result;
  const auto blocked = [&](std::size_t index, const std::string &reason) {
    const auto &f = functions[index];
    std::ostringstream address, size;
    address << "0x" << std::hex << f.address;
    size << "0x" << std::hex << f.size;
    records[index] = Object{{"name", f.name},
                            {"address", address.str()},
                            {"size", size.str()},
                            {"discovery_evidence", Array{f.source}},
                            {"boundary_known", f.size != 0},
                            {"status", "BLOCKED"},
                            {"instruction_count", nullptr},
                            {"unsupported_instructions", Array{}},
                            {"unresolved_edges", Array{}},
                            {"llvm_verified", false},
                            {"tested_cases", 0},
                            {"reason", reason}};
    result.blocked++;
  };
  while (next < functions.size() || !active.empty()) {
    while (next < functions.size() && active.size() < jobs) {
      const auto index = next++;
      if (!functions[index].size) {
        blocked(index, "No function boundary");
        continue;
      }
      auto directory = output / ("function-" + std::to_string(index));
      pid_t pid = fork();
      if (pid < 0) {
        blocked(index, "Cannot fork worker");
        continue;
      }
      if (!pid) {
        const rlimit cpu{(timeout + 999) / 1000 + 1,
                         (timeout + 999) / 1000 + 1};
        rlim_t allowance = 2ULL * 1024 * 1024 * 1024;
#ifdef ZVRIL_SANITIZED
        // ASan reserves a large shadow map before fork. Bound additional VM
        // without placing the existing shadow reservation above RLIMIT_AS.
        std::ifstream statm("/proc/self/statm");
        std::uint64_t pages = 0;
        if (!(statm >> pages) ||
            pages > UINT64_MAX / std::uint64_t(sysconf(_SC_PAGESIZE)))
          _exit(1);
        allowance += pages * std::uint64_t(sysconf(_SC_PAGESIZE));
#endif
        const rlimit memory{allowance, allowance};
        if (setrlimit(RLIMIT_CPU, &cpu) || setrlimit(RLIMIT_AS, &memory))
          _exit(1);
        Object report;
        int code = 2;
        try {
          code = action(functions[index], directory, report);
        } catch (...) {
        }
        _exit(code);
      }
      active.emplace(
          pid, Active{index, std::chrono::steady_clock::now(), directory});
    }
    for (auto it = active.begin(); it != active.end();) {
      int status = 0;
      auto pid = waitpid(it->first, &status, WNOHANG);
      if (!pid && std::chrono::steady_clock::now() - it->second.start <
                      std::chrono::milliseconds(timeout)) {
        ++it;
        continue;
      }
      if (!pid) {
        kill(it->first, SIGKILL);
        while (waitpid(it->first, &status, 0) < 0 && errno == EINTR) {
        }
        blocked(it->second.index, "Worker deadline exceeded");
      } else {
        const auto report_path = it->second.output / "report.json";
        std::error_code error;
        if (std::filesystem::is_regular_file(report_path, error) &&
            std::filesystem::file_size(report_path, error) < 64 * 1024 * 1024) {
          std::ifstream file(report_path);
          std::string text((std::istreambuf_iterator<char>(file)), {});
          auto parsed = llvm::json::parse(text);
          bool accepted = false;
          if (parsed)
            if (auto *object = parsed->getAsObject())
              if (auto *rows = object->getArray("functions"))
                for (const auto &row : *rows)
                  if (auto *f = row.getAsObject()) {
                    std::ostringstream target;
                    target << "0x" << std::hex
                           << functions[it->second.index].address;
                    if (f->getString("address").value_or("") == target.str()) {
                      auto item = *f;
                      item["output"] = it->second.output.string();
                      const bool success =
                          WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
                          f->getString("status").value_or("") == "LIFTED";
                      if (!success) {
                        item["status"] = "BLOCKED";
                        item["reason"] =
                            "Worker did not complete successfully; prior "
                            "artifacts are not success evidence";
                      }
                      records[it->second.index] = std::move(item);
                      if (success)
                        result.lifted++;
                      else
                        result.blocked++;
                      accepted = true;
                      break;
                    }
                  }
          if (!parsed)
            llvm::consumeError(parsed.takeError());
          if (!accepted)
            blocked(it->second.index, "Worker failed; inspect its diagnostics");
        } else
          blocked(it->second.index, "Worker exited without a report");
      }
      it = active.erase(it);
    }
    if (!active.empty())
      std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
  for (auto &[_, record] : records)
    result.functions.push_back(std::move(record));
  return result;
}
} // namespace zvril
