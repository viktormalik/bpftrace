#include "dibuilderbpf.h"

#include "libbpf/bpf.h"
#include "log.h"
#include "struct.h"
#include "utils.h"

#include <llvm/IR/Function.h>

namespace bpftrace::ast {

DIBuilderBPF::DIBuilderBPF(Module &module) : DIBuilder(module)
{
  file = createFile("bpftrace.bpf.o", ".");
}

void DIBuilderBPF::createFunctionDebugInfo(Function &func,
                                           const SizedType &ret_type,
                                           const Struct &args)
{
  // Return type should be at index 0
  SmallVector<Metadata *> types;
  types.reserve(args.fields.size() + 1);
  types.push_back(GetType(ret_type, false));
  for (auto &arg : args.fields)
    types.push_back(GetType(arg.type, false));

  DISubroutineType *ditype = createSubroutineType(getOrCreateTypeArray(types));

  std::string sanitised_name = sanitise_bpf_program_name(func.getName().str());

  DISubprogram::DISPFlags flags = DISubprogram::SPFlagDefinition;
  if (func.isLocalLinkage(func.getLinkage()))
    flags |= DISubprogram::DISPFlags::SPFlagLocalToUnit;

  DISubprogram *subprog = createFunction(file,
                                         sanitised_name,
                                         sanitised_name,
                                         file,
                                         0,
                                         ditype,
                                         0,
                                         DINode::FlagPrototyped,
                                         flags);

  for (size_t i = 0; i < args.fields.size(); i++) {
    createParameterVariable(subprog,
                            args.fields.at(i).name,
                            i + 1,
                            file,
                            0,
                            static_cast<DIType *>(types[i + 1]),
                            true);
  }

  func.setSubprogram(subprog);
}

void DIBuilderBPF::createProbeDebugInfo(Function &probe_func)
{
  // BPF probe function has:
  // - int return type
  // - single parameter (ctx) of a pointer type
  Struct args;
  args.AddField("ctx", CreatePointer(CreateInt8()));
  createFunctionDebugInfo(probe_func, CreateInt64(), args);
}

DIType *DIBuilderBPF::getInt8Ty()
{
  if (!types_.int8)
    types_.int8 = createBasicType("int8", 8, dwarf::DW_ATE_signed);

  return types_.int8;
}

DIType *DIBuilderBPF::getInt16Ty()
{
  if (!types_.int16)
    types_.int16 = createBasicType("int16", 16, dwarf::DW_ATE_signed);

  return types_.int16;
}

DIType *DIBuilderBPF::getInt32Ty()
{
  if (!types_.int32)
    types_.int32 = createBasicType("int32", 32, dwarf::DW_ATE_signed);

  return types_.int32;
}

DIType *DIBuilderBPF::getInt64Ty()
{
  if (!types_.int64)
    types_.int64 = createBasicType("int64", 64, dwarf::DW_ATE_signed);

  return types_.int64;
}

DIType *DIBuilderBPF::getIntTy()
{
  if (!types_.int_)
    types_.int_ = createBasicType("int", 32, dwarf::DW_ATE_signed);

  return types_.int_;
}

DIType *DIBuilderBPF::getInt8PtrTy()
{
  if (!types_.int8_ptr)
    types_.int8_ptr = createPointerType(getInt8Ty(), 64);

  return types_.int8_ptr;
}

// Create anonymous struct with anonymous fields. It's possible that there will
// be multiple tuples of the same (duplicated) type but BTF deduplication should
// take care of that.
DIType *DIBuilderBPF::CreateTupleType(const SizedType &stype)
{
  assert(stype.IsTupleTy());

  SmallVector<Metadata *, 8> fields;
  for (auto &field : stype.GetFields()) {
    fields.push_back(createMemberType(file,
                                      "",
                                      file,
                                      0,
                                      field.type.GetSize() * 8,
                                      0,
                                      field.offset * 8,
                                      DINode::FlagZero,
                                      GetType(field.type)));
  }
  DICompositeType *result = createStructType(file,
                                             "",
                                             file,
                                             0,
                                             stype.GetSize() * 8,
                                             0,
                                             DINode::FlagZero,
                                             nullptr,
                                             getOrCreateArray(fields));
  return result;
}

DIType *DIBuilderBPF::CreateMapStructType(const SizedType &stype)
{
  assert(stype.IsMinTy() || stype.IsMaxTy() || stype.IsAvgTy() ||
         stype.IsStatsTy());

  // For Min/Max, the first field is the value and the second field is the
  // "value is set" flag. For Avg/Stats, the first field is the total and the
  // second field is the count.
  SmallVector<Metadata *, 2> fields = { createMemberType(file,
                                                         "",
                                                         file,
                                                         0,
                                                         stype.GetSize() * 8,
                                                         0,
                                                         0,
                                                         DINode::FlagZero,
                                                         getInt64Ty()),
                                        createMemberType(file,
                                                         "",
                                                         file,
                                                         0,
                                                         stype.GetSize() * 8,
                                                         0,
                                                         stype.GetSize() * 8,
                                                         DINode::FlagZero,
                                                         getInt32Ty()) };

  DICompositeType *result = createStructType(file,
                                             "",
                                             file,
                                             0,
                                             (stype.GetSize() * 8) * 2,
                                             0,
                                             DINode::FlagZero,
                                             nullptr,
                                             getOrCreateArray(fields));
  return result;
}

DIType *DIBuilderBPF::CreateByteArrayType(uint64_t num_bytes)
{
  auto subrange = getOrCreateSubrange(0, num_bytes);
  return createArrayType(
      num_bytes * 8, 0, getInt8Ty(), getOrCreateArray({ subrange }));
}

DIType *DIBuilderBPF::GetType(const SizedType &stype, bool emit_codegen_types)
{
  if (!emit_codegen_types && stype.IsRecordTy()) {
    return createStructType(file,
                            stype.GetName(),
                            file,
                            0,
                            stype.GetSize() * 8,
                            0,
                            DINode::FlagZero,
                            nullptr,
                            getOrCreateArray({}));
  }

  if (stype.IsByteArray() || stype.IsRecordTy()) {
    auto subrange = getOrCreateSubrange(0, stype.GetSize());
    return createArrayType(
        stype.GetSize() * 8, 0, getInt8Ty(), getOrCreateArray({ subrange }));
  }

  if (stype.IsArrayTy()) {
    auto subrange = getOrCreateSubrange(0, stype.GetNumElements());
    return createArrayType(stype.GetSize() * 8,
                           0,
                           GetType(*stype.GetElementTy()),
                           getOrCreateArray({ subrange }));
  }

  if (stype.IsTupleTy())
    return CreateTupleType(stype);

  if (stype.IsMinTy() || stype.IsMaxTy() || stype.IsAvgTy() ||
      stype.IsStatsTy())
    return CreateMapStructType(stype);

  if (stype.IsPtrTy())
    return emit_codegen_types ? getInt64Ty()
                              : createPointerType(GetType(*stype.GetPointeeTy(),
                                                          emit_codegen_types),
                                                  64);

  // Integer types and builtin types represented by integers
  switch (stype.GetSize()) {
    case 8:
      return getInt64Ty();
    case 4:
      return getInt32Ty();
    case 2:
      return getInt16Ty();
    case 1:
      return getInt8Ty();
    default:
      LOG(BUG) << "Cannot generate debug info for type "
               << typestr(stype.GetTy()) << " (" << stype.GetSize()
               << " is not a valid type size)";
      return nullptr;
  }
}

DIType *DIBuilderBPF::GetMapKeyType(const SizedType &key_type,
                                    const SizedType &value_type,
                                    libbpf::bpf_map_type map_type)
{
  // No-key maps use '0' as the key.
  // - BPF requires 4-byte keys for array maps
  // - bpftrace uses 8 bytes for the implicit '0' key in hash maps
  if (key_type.IsNoneTy())
    return (map_type == libbpf::BPF_MAP_TYPE_PERCPU_ARRAY ||
            map_type == libbpf::BPF_MAP_TYPE_ARRAY)
               ? getInt32Ty()
               : getInt64Ty();

  // Some map types need an extra 8-byte key.
  if (value_type.IsHistTy() || value_type.IsLhistTy()) {
    uint64_t size = key_type.GetSize() + 8;
    return CreateByteArrayType(size);
  }

  return GetType(key_type);
}

DIType *DIBuilderBPF::GetMapFieldInt(int value)
{
  // Integer fields of map entry are represented by 64-bit pointers to an array
  // of int, in which dimensionality of the array encodes the specified value.
  auto subrange = getOrCreateSubrange(0, value);
  auto array = createArrayType(
      32 * value, 0, getIntTy(), getOrCreateArray({ subrange }));
  return createPointerType(array, 64);
}

DIType *DIBuilderBPF::createPointerMemberType(const std::string &name,
                                              uint64_t offset,
                                              DIType *type)
{
  return createMemberType(
      file, name, file, 0, 64, 0, offset, DINode::FlagZero, type);
}

DIGlobalVariableExpression *DIBuilderBPF::createMapEntry(
    const std::string &name,
    libbpf::bpf_map_type map_type,
    uint64_t max_entries,
    DIType *key_type,
    const SizedType &value_type)
{
  SmallVector<Metadata *, 4> fields = {
    createPointerMemberType("type", 0, GetMapFieldInt(map_type)),
    createPointerMemberType("max_entries", 64, GetMapFieldInt(max_entries)),
  };

  uint64_t size = 128;
  if (!value_type.IsNoneTy()) {
    fields.push_back(
        createPointerMemberType("key", size, createPointerType(key_type, 64)));
    fields.push_back(createPointerMemberType(
        "value", size + 64, createPointerType(GetType(value_type), 64)));
    size += 128;
  }

  DIType *map_entry_type = createStructType(file,
                                            "",
                                            file,
                                            0,
                                            size,
                                            0,
                                            DINode::FlagZero,
                                            nullptr,
                                            getOrCreateArray(fields));
  return createGlobalVariableExpression(
      file, name, "global", file, 0, map_entry_type, false);
}

DIGlobalVariableExpression *DIBuilderBPF::createGlobalVariable(
    std::string_view name,
    const SizedType &stype)
{
  return createGlobalVariableExpression(
      file, name, "global", file, 0, GetType(stype), false);
}

} // namespace bpftrace::ast
