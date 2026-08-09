load("@build_bazel_rules_swift//swift:swift.bzl", "swift_library")

objc_library(
    name = "_AtomicsShims",
    srcs = glob([
        "swift-atomics/Sources/_AtomicsShims/**/*.c",
        "swift-atomics/Sources/_AtomicsShims/**/*.h",
    ]),
    hdrs = glob(["swift-atomics/Sources/_AtomicsShims/include/**/*.h"]),
    includes = [
        "swift-atomics/Sources/_AtomicsShims/include",
    ],
    module_name = "_AtomicsShims",
    visibility = ["//visibility:public"],
)

swift_library(
    name = "Atomics",
    srcs = glob(
        ["swift-atomics/Sources/Atomics/**/*.swift"],
        exclude = ["swift-atomics/Sources/Atomics/**/*.gyb"],
    ),
    module_name = "Atomics",
    copts = [
        "-package-name", "swift-atomics",
        "-enable-experimental-feature", "BuiltinModule",
    ],
    visibility = ["//visibility:public"],
    deps = [
        ":_AtomicsShims",
    ],
)