set(ARTB_UASM_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../upstream/uasm" CACHE PATH "UASM v2.57r source root")
if(NOT EXISTS "${ARTB_UASM_ROOT}/main.c" OR NOT EXISTS "${ARTB_UASM_ROOT}/H/globals.h")
    message(FATAL_ERROR "UASM sources missing under ${ARTB_UASM_ROOT}")
endif()
# Same object list as upstream gccLinux64.mak and gccmod.inc.
set(ARTB_UASM_SOURCES main.c apiemu.c orgfixup.c assemble.c assume.c atofloat.c backptch.c bin.c branch.c cmdline.c codegen.c codegenv2.c coff.c condasm.c context.c cpumodel.c data.c dbgcv.c directiv.c elf.c end.c equate.c errmsg.c expans.c expreval.c extern.c fastpass.c fixup.c fpfixup.c hll.c input.c invoke.c label.c linnum.c listing.c loop.c lqueue.c ltype.c macho64.c macro.c macrolib.c mangle.c memalloc.c msgtext.c omf.c omffixup.c omfint.c option.c parser.c posndir.c preproc.c proc.c queue.c reswords.c safeseh.c segment.c simd.c simsegm.c string.c symbols.c tbyte.c pseudoFilter.c tokenize.c types.c)
list(TRANSFORM ARTB_UASM_SOURCES PREPEND "${ARTB_UASM_ROOT}/")
add_executable(artb_uasm ${ARTB_UASM_SOURCES})
set_target_properties(artb_uasm PROPERTIES OUTPUT_NAME uasm C_STANDARD 99)
target_include_directories(artb_uasm PRIVATE "${ARTB_UASM_ROOT}/H")
target_compile_definitions(artb_uasm PRIVATE __UNIX__ NDEBUG)
# Upstream's own flags plus the pre-GCC-14 treatment of implicit declarations and pointer mismatches; only strupr returns a pointer and it gets a prototype in globals.h.
target_compile_options(artb_uasm PRIVATE -funsigned-char -w -Wno-error=implicit-function-declaration -Wno-error=incompatible-pointer-types -Wno-error=int-conversion)
