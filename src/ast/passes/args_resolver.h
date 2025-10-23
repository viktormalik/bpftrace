#pragma once

#include "ast/pass_manager.h"
#include "probe_types.h"

namespace bpftrace::ast {

class ProbeArgParseError : public ErrorInfo<ProbeArgParseError> {
public:
  static char ID;
  ProbeArgParseError(std::string probe_name, std::string &&detail)
      : probe_name_(std::move(probe_name)), detail_(std::move(detail)) {};
  ProbeArgParseError(std::string_view probe_name, std::string &&detail)
      : ProbeArgParseError(std::string(probe_name), std::move(detail)) {};
  void log(llvm::raw_ostream &OS) const override;

private:
  std::string probe_name_;
  std::string detail_;
};

Pass CreateArgsResolverPass(std::vector<ProbeType>&& probe_types = {
    ProbeType::fentry,
    ProbeType::fexit,
    ProbeType::rawtracepoint,
    ProbeType::uprobe,
});

} // namespace bpftrace::ast
