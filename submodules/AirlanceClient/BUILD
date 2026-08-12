load("@build_bazel_rules_swift//swift:swift.bzl", "swift_library")

swift_library(
    name = "AirlanceClient",
    srcs = glob([
        "Sources/AirlanceClient/*.swift",
        "Sources/AirlanceClient/Noise/*.swift",
        "Sources/AirlanceClient/Protocol/*.swift"
    ]),
    module_name = "AirlanceClient",
    visibility = ["//visibility:public"],
    deps = [
        "//third-party/FlatBuffers:FlatBuffers",
    ],
)
