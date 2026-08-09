load("@build_bazel_rules_swift//swift:swift.bzl", "swift_library")

swift_nio_copts = [
    "-package-name", "swift-nio",
    "-enable-experimental-feature", "Lifetimes",
    "-enable-upcoming-feature", "MemberImportVisibility",
]

objc_library(
    name = "CNIOAtomics",
    srcs = glob([
        "swift-nio/Sources/CNIOAtomics/**/*.c",
        "swift-nio/Sources/CNIOAtomics/src/**/*.h",
    ]),
    hdrs = glob(["swift-nio/Sources/CNIOAtomics/include/**/*.h"]),
    includes = [
        "swift-nio/Sources/CNIOAtomics/include",
        "swift-nio/Sources/CNIOAtomics/src",
    ],
    copts = ["-D_GNU_SOURCE"],
    module_name = "CNIOAtomics",
    visibility = ["//visibility:public"],
)

objc_library(
    name = "CNIOLLHTTP",
    srcs = glob(["swift-nio/Sources/CNIOLLHTTP/**/*.c", "swift-nio/Sources/CNIOLLHTTP/**/*.h"], allow_empty = True),
    hdrs = glob(["swift-nio/Sources/CNIOLLHTTP/include/**/*.h"], allow_empty = True),
    includes = ["swift-nio/Sources/CNIOLLHTTP/include"],
    copts = ["-D_GNU_SOURCE", "-DLLHTTP_STRICT_MODE"],
    module_name = "CNIOLLHTTP",
    visibility = ["//visibility:public"],
)

objc_library(
    name = "CNIODarwin",
    srcs = glob(["swift-nio/Sources/CNIODarwin/**/*.c", "swift-nio/Sources/CNIODarwin/**/*.h"], allow_empty = True),
    hdrs = glob(["swift-nio/Sources/CNIODarwin/include/**/*.h"], allow_empty = True),
    includes = ["swift-nio/Sources/CNIODarwin/include"],
    copts = ["-D__APPLE_USE_RFC_3542"],
    module_name = "CNIODarwin",
    visibility = ["//visibility:public"],
)

objc_library(
    name = "CNIOLinux",
    srcs = glob(["swift-nio/Sources/CNIOLinux/**/*.c", "swift-nio/Sources/CNIOLinux/**/*.h"], allow_empty = True),
    hdrs = glob(["swift-nio/Sources/CNIOLinux/include/**/*.h"], allow_empty = True),
    includes = ["swift-nio/Sources/CNIOLinux/include"],
    copts = ["-D_GNU_SOURCE"],
    module_name = "CNIOLinux",
    visibility = ["//visibility:public"],
)

objc_library(
    name = "CNIOOpenBSD",
    srcs = glob(["swift-nio/Sources/CNIOOpenBSD/**/*.c", "swift-nio/Sources/CNIOOpenBSD/**/*.h"], allow_empty = True),
    hdrs = glob(["swift-nio/Sources/CNIOOpenBSD/include/**/*.h"], allow_empty = True),
    includes = ["swift-nio/Sources/CNIOOpenBSD/include"],
    module_name = "CNIOOpenBSD",
    visibility = ["//visibility:public"],
)

objc_library(
    name = "CNIOWindows",
    srcs = glob(["swift-nio/Sources/CNIOWindows/**/*.c", "swift-nio/Sources/CNIOWindows/**/*.h"], allow_empty = True),
    hdrs = glob(["swift-nio/Sources/CNIOWindows/include/**/*.h"], allow_empty = True),
    includes = ["swift-nio/Sources/CNIOWindows/include"],
    module_name = "CNIOWindows",
    visibility = ["//visibility:public"],
)

objc_library(
    name = "CNIOPosix",
    srcs = glob(["swift-nio/Sources/CNIOPosix/**/*.c", "swift-nio/Sources/CNIOPosix/**/*.h"], allow_empty = True),
    hdrs = glob(["swift-nio/Sources/CNIOPosix/include/**/*.h"], allow_empty = True),
    includes = ["swift-nio/Sources/CNIOPosix/include"],
    copts = ["-D_GNU_SOURCE"],
    module_name = "CNIOPosix",
    visibility = ["//visibility:public"],
)

swift_library(
    name = "_NIODataStructures",
    srcs = glob(["swift-nio/Sources/_NIODataStructures/**/*.swift"]),
    module_name = "_NIODataStructures",
    copts = swift_nio_copts,
    visibility = ["//visibility:public"],
)

swift_library(
    name = "_NIOBase64",
    srcs = glob(["swift-nio/Sources/_NIOBase64/**/*.swift"]),
    module_name = "_NIOBase64",
    copts = swift_nio_copts,
    visibility = ["//visibility:public"],
)

swift_library(
    name = "NIOConcurrencyHelpers",
    srcs = glob(["swift-nio/Sources/NIOConcurrencyHelpers/**/*.swift"]),
    module_name = "NIOConcurrencyHelpers",
    visibility = ["//visibility:public"],
    copts = swift_nio_copts,
    deps = [
        ":CNIOAtomics",
    ],
)

swift_library(
    name = "NIOHTTP1",
    srcs = glob(["swift-nio/Sources/NIOHTTP1/**/*.swift"]),
    module_name = "NIOHTTP1",
    visibility = ["//visibility:public"],
    copts = swift_nio_copts,
    deps = [
        ":NIOCore",
        ":CNIOLLHTTP",
    ],
)

swift_library(
    name = "NIOTLS",
    srcs = glob(["swift-nio/Sources/NIOTLS/**/*.swift"]),
    module_name = "NIOTLS",
    visibility = ["//visibility:public"],
    copts = swift_nio_copts,
    deps = [
        ":NIOCore",
    ],
)

swift_library(
    name = "NIOFoundationCompat",
    srcs = glob(["swift-nio/Sources/NIOFoundationCompat/**/*.swift"]),
    module_name = "NIOFoundationCompat",
    visibility = ["//visibility:public"],
    copts = swift_nio_copts,
    deps = [
        ":NIOFoundationEssentialsCompat",
    ],
)

swift_library(
    name = "NIOFoundationEssentialsCompat",
    srcs = glob(["swift-nio/Sources/NIOFoundationEssentialsCompat/**/*.swift"]),
    module_name = "NIOFoundationEssentialsCompat",
    visibility = ["//visibility:public"],
    copts = swift_nio_copts,
    deps = [
        ":NIOCore",
    ],
)

swift_library(
    name = "NIOCore",
    srcs = glob(["swift-nio/Sources/NIOCore/**/*.swift"]),
    module_name = "NIOCore",
    visibility = ["//visibility:public"],
    copts = swift_nio_copts,
    deps = [
        "//third-party/swift-collections:DequeModule",
        "//third-party/swift-atomics:Atomics",
        ":_NIODataStructures",
        "_NIOBase64",
        ":NIOConcurrencyHelpers",
    ],
)

swift_library(
    name = "NIOPosix",
    srcs = glob(["swift-nio/Sources/NIOPosix/**/*.swift"]),
    module_name = "NIOPosix",
    visibility = ["//visibility:public"],
    copts = swift_nio_copts,
    deps = [
        ":NIOCore",
        ":CNIODarwin",
        ":CNIOLinux",
        ":CNIOOpenBSD",
        ":CNIOPosix",
        ":CNIOWindows",
    ],
)