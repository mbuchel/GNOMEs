# Download ELFIO
ExternalProject_Add(
    elfio
    PREFIX "vendor/elfio"
    GIT_REPOSITORY "https://github.com/serge1/ELFIO.git"
    GIT_TAG 182248f364e6375eaad30cefdd6b67660abaa3b3
    TIMEOUT 10
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ""
    INSTALL_COMMAND ""
    UPDATE_COMMAND ""
)

# Prepare ELFIO headers
ExternalProject_Get_Property(elfio source_dir)
set(ELFIO_INCLUDE_DIR ${source_dir})
