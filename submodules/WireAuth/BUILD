load("@build_bazel_rules_swift//swift:swift.bzl", "swift_library")

swift_library(
    name = "WireAuth",
    module_name = "WireAuth",
    srcs = glob([
        "Sources/**/*.swift",
    ]),
    copts = [
        "-warnings-as-errors",
    ],
    visibility = [
        "//visibility:public",
    ],
)
