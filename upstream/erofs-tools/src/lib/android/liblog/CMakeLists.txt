set(TARGET log_static)

set(TARGET_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR})

set(TARGET_CFLAGS
    "-Wall"
    "-Werror"
    "-Wextra"
    "-DLIBLOG_LOG_TAG=1006"
    "-DSNET_EVENT_LOG_TAG=1397638484"
    "-U__ANDROID__"
)
if (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    list(APPEND TARGET_CFLAGS "-Wexit-time-destructors" "-Wno-c99-designator")
endif ()

set(liblog_srcs
    "log.cpp"
)

list(TRANSFORM liblog_srcs PREPEND "${TARGET_SRC_DIR}/")

add_library(${TARGET} STATIC ${liblog_srcs})

target_include_directories(${TARGET} PUBLIC
    "${TARGET_SRC_DIR}/include"
)

target_compile_options(${TARGET} PRIVATE
    "$<$<COMPILE_LANGUAGE:C>:${TARGET_CFLAGS}>"
    "$<$<COMPILE_LANGUAGE:CXX>:${TARGET_CFLAGS}>"
)
