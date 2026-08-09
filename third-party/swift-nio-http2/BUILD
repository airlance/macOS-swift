load("@build_bazel_rules_swift//swift:swift.bzl", "swift_library")

swift_nio_http2_copts = [
    "-package-name", "swift-nio-http2",
    "-enable-upcoming-feature", "MemberImportVisibility",
]

swift_library(
    name = "NIOHPACK",
    srcs = glob(["swift-nio-http2/Sources/NIOHPACK/**/*.swift"]),
    module_name = "NIOHPACK",
    visibility = ["//visibility:public"],
    copts = swift_nio_http2_copts,
    deps = [
        "//third-party/swift-nio:NIOCore",
        "//third-party/swift-nio:NIOHTTP1",
    ],
)

swift_library(
    name = "NIOHTTP2",
    srcs = glob(["swift-nio-http2/Sources/NIOHTTP2/**/*.swift"]),
    module_name = "NIOHTTP2",
    visibility = ["//visibility:public"],
    copts = swift_nio_http2_copts,
    deps = [
        ":NIOHPACK",
        "//third-party/swift-nio:NIOCore",
        "//third-party/swift-nio:NIOTLS"
    ],
)