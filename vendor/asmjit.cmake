# Download AsmJIT
ExternalProject_Add(
    asmjit
    PREFIX "vendor/asmjit"
    GIT_REPOSITORY "https://github.com/asmjit/asmjit.git"
    GIT_TAG master
    TIMEOUT 10
    CMAKE_ARGS
        -DASMJIT_STATIC=ON
    BUILD_COMMAND ${CMAKE_COMMAND} --build <BINARY_DIR>
    INSTALL_COMMAND ""
    UPDATE_COMMAND ""
)

ExternalProject_Get_Property(asmjit source_dir)
set(ASMJIT_INCLUDE_DIR ${source_dir}/src)
set(ASMJIT_SOURCE_DIR ${source_dir})
set(ASMJIT_LIBRARY ${source_dir}/../asmjit-build/libasmjit.a)
