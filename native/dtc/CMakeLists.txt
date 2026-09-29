set(ARTB_DTC_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../upstream/dtc")
# The lexer and parser are generated once from dtc-lexer.l and dtc-parser.y and vendored, so builds need no flex or bison.
set(ARTB_DTC_SOURCES checks.c data.c dtc.c flattree.c fstree.c livetree.c srcpos.c treesource.c util.c dtc-lexer.lex.c dtc-parser.tab.c)
list(TRANSFORM ARTB_DTC_SOURCES PREPEND "${ARTB_DTC_ROOT}/")
add_executable(dtc ${ARTB_DTC_SOURCES})
target_include_directories(dtc PRIVATE "${ARTB_DTC_ROOT}" "${ARTB_DTC_ROOT}/libfdt")
target_compile_definitions(dtc PRIVATE NO_YAML)
target_compile_options(dtc PRIVATE -w)
if(WIN32)
    # Blobs travel through stdin and stdout, which must not translate line endings; the manifest keeps Unicode include paths working.
    target_sources(dtc PRIVATE "${CMAKE_CURRENT_LIST_DIR}/artb_dtc_binary_mode.c" "${ARTB_UTF8_MANIFEST_RC}")
endif()
