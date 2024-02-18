# Download AsmTK
ExternalProject_Add(
    asmtk
    PREFIX "vendor/asmtk"
    GIT_REPOSITORY "https://github.com/asmjit/asmtk.git"
    GIT_TAG master
    TIMEOUT 10
    CMAKE_ARGS
        -DASMJIT_DIR=${ASMJIT_SOURCE_DIR}
        -DASMJIT_STATIC=ON
        -DASMTK_STATIC=ON
    BUILD_COMMAND ${CMAKE_COMMAND} --build <BINARY_DIR>
    INSTALL_COMMAND ""
    UPDATE_COMMAND ""
)

ExternalProject_Get_Property(asmtk source_dir)
set(ASMTK_INCLUDE_DIR ${source_dir}/src)
set(ASMTK_LIBRARY ${source_dir}/../asmtk-build/libasmtk.a)
