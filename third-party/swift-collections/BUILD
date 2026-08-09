load("@build_bazel_rules_swift//swift:swift.bzl", "swift_library")

swift_collections_copts = [
    "-package-name", "swift-collections",
    "-enable-experimental-feature", "BuiltinModule",
    "-enable-experimental-feature", "Lifetimes",
    "-enable-experimental-feature", "InoutLifetimeDependence",
    "-enable-experimental-feature", "AddressableParameters",
    "-enable-experimental-feature", "AddressableTypes",
]

swift_library(
    name = "InternalCollectionsUtilities",
    srcs = glob(["swift-collections/Sources/InternalCollectionsUtilities/**/*.swift"]),
    module_name = "InternalCollectionsUtilities",
    visibility = ["//visibility:public"],
    copts = swift_collections_copts,
)

swift_library(
    name = "ContainersPreview",
    srcs = glob(["swift-collections/Sources/ContainersPreview/**/*.swift"]),
    module_name = "ContainersPreview",
    visibility = ["//visibility:public"],
    copts = swift_collections_copts,
    deps = [
        ":InternalCollectionsUtilities",
    ],
)

swift_library(
    name = "DequeModule",
    srcs = glob(["swift-collections/Sources/DequeModule/**/*.swift"]),
    module_name = "DequeModule",
    visibility = ["//visibility:public"],
    copts = swift_collections_copts,
    deps = [
        ":InternalCollectionsUtilities",
        ":ContainersPreview",
    ],
)
