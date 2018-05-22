# -------------------------------------------------------------------------------------------------- #
# сборка по умолчанию
# cmake path && make
# где path это путь к каталогу, в котором расположен файл MakeLists.txt

# сборка с использованием с использованием clang
# cmake -D CMAKE_C_COMPILER=clang path && make

# сборка с использованием с использованием TinyCC
# cmake -D CMAKE_C_COMPILER=tcc path && make

# сборка при помощи MSVC из консоли (Visual Studio Console Prompt)
# cmake -G "NMake Makefiles" path && nmake

# сборка при MinGW из консоли MSYS (WINDOWS)
# cmake -G "MinGW Makefiles" -D CMAKE_C_COMPILER=gcc path && mingw32-make
# -------------------------------------------------------------------------------------------------- #
cmake_minimum_required( VERSION 3.2 )
project( libakrypt )

set( HEAD_VERSION 0 )
set( MAIN_VERSION 6 )
set( MINOR_VERSION 4 )

set( MAJOR_VERSION ${HEAD_VERSION}.${MAIN_VERSION} )
set( FULL_VERSION ${MAJOR_VERSION}.${MINOR_VERSION} )

# для включения опции cmake -D LIBAKRYPT_GMP_TESTS=ON path
option( LIBAKRYPT_STATIC_LIB "Build the static library" ON )
option( LIBAKRYPT_SHARED_LIB "Build the shared library" OFF )
option( LIBAKRYPT_GMP_TESTS "Build test programs with libGMP" OFF)
option( LIBAKRYPT_BIG_ENDIAN "Using a code for big endian architectures" OFF )

# -------------------------------------------------------------------------------------------------- #
# множество исходных текстов библиотеки
set( MAIN_HEADER    source/libakrypt.h )

set( HEADERS        source/ak_tools.h
                    source/ak_context_manager.h
                    source/ak_buffer.h
                    source/ak_random.h
                    source/ak_parameters.h
                    source/ak_oid.h
                    source/ak_hash.h
                    source/ak_compress.h
                    source/ak_skey.h
                    source/ak_bckey.h
                    source/ak_mac.h
                    source/ak_mpzn.h
                    source/ak_curves.h
                    source/ak_sign.h
)

set( SOURCES        source/ak_log.c
                    source/ak_libakrypt.c
                    source/ak_tools.c
                    source/ak_context_manager.c
                    source/ak_buffer.c
                    source/ak_random.c
                    source/ak_oid.c
                    source/ak_hash.c
                    source/ak_gosthash.c
                    source/ak_streebog.c
                    source/ak_compress.c
                    source/ak_skey.c
                    source/ak_bckey.c
                    source/ak_magma.c
                    source/ak_kuznechik.c
                    source/ak_mac.c
                    source/ak_hmac.c
                    source/ak_mpzn.c
                    source/ak_curves.c
                    source/ak_sign.c
                    source/ak_sha256.c
                    source/ak_sha512.c
)

set( DOCS           doc/libakrypt.dox
                    doc/refman_header.in
                    doc/refman_footer.in
                    doc/Doxyfile.in )

set( CMAKES         cmake/DetectHeaders.cmake
                    cmake/DetectFlags.cmake
                    cmake/DetectLibraries.cmake
                    cmake/DetectIntrinsics.cmake
                    cmake/MakeDoc.cmake
                    cmake/MakeDist.cmake
                    cmake/MakeInstall.cmake )

set( OTHERS         CMakeLists.txt
                    Readme.md
                    Changelog.md
                    libakrypt.rc.in
                    libakrypt.conf )

set( AKRYPT_SOURCES akrypt/akrypt.c
                    akrypt/akrypt_icode.c
                    akrypt/akrypt_show.c
)

set( AKRYPT_FILES   akrypt/akrypt.h
                    akrypt/akrypt.1
                    akrypt/getopt.h
                    akrypt/getopt.c
)

# -------------------------------------------------------------------------------------------------- #
# подключаем модули CMake для тонкой настройки параметров сборки
set( CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake ${CMAKE_MODULE_PATH} )
include( DetectHeaders )
include( DetectLibraries )
include( DetectIntrinsics )
include( DetectFlags )

# -------------------------------------------------------------------------------------------------- #
# определяемся с местом хранения файла с конфигурацией библиотеки
if( LIBAKRYPT_CONF )
else()
  if( CMAKE_HOST_UNIX )
    set( LIBAKRYPT_CONF "/etc" )
  endif()
  if( CMAKE_HOST_WINDOWS )
    set( LIBAKRYPT_CONF "C:\\Program Files\\Akrypt" )
  endif()
endif()

# -------------------------------------------------------------------------------------------------- #
# определяемся с архитектурой
if( LIBAKRYPT_BIG_ENDIAN )
  set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLIBAKRYPT_BIG_ENDIAN" )
endif()

# -------------------------------------------------------------------------------------------------- #
# сборка библиотек - статической и, если нужно, динамической
include_directories( "source " )
add_compile_options( -DLIBAKRYPT_VERSION="${FULL_VERSION}" )
if( LIBAKRYPT_CONF )
    message("-- Path for libakrypt.conf is ${LIBAKRYPT_CONF}")
    add_compile_options( -DLIBAKRYPT_OPTIONS_PATH="${LIBAKRYPT_CONF}" )
endif()

if( LIBAKRYPT_SHARED_LIB )
  add_library( akrypt-shared SHARED ${MAIN_HEADER} ${SOURCES} ${ASN1_SOURCES})
  set_target_properties( akrypt-shared PROPERTIES VERSION ${MAJOR_VERSION} SOVERSION ${FULL_VERSION} )
  target_link_libraries( akrypt-shared ${LIBAKRYPT_LIBS} )
endif()
#
if( LIBAKRYPT_STATIC_LIB )
  add_library( akrypt-static STATIC ${MAIN_HEADER} ${SOURCES} ${ASN1_SOURCES})
  set_target_properties( akrypt-static PROPERTIES VERSION ${MAJOR_VERSION} SOVERSION ${FULL_VERSION} )
endif()

# -------------------------------------------------------------------------------------------------- #
message("-- Additional libraries is ${LIBAKRYPT_LIBS}" )

# -------------------------------------------------------------------------------------------------- #
# сборка консольной утилиты
if( LIBAKRYPT_HAVE_GETOPT )
else()
  set( AKRYPT_SOURCES ${AKRYPT_SOURCES} akrypt/getopt.c )
endif()
add_executable( akrypt${LIBAKRYPT_EXT} ${AKRYPT_SOURCES} )
target_include_directories( akrypt${LIBAKRYPT_EXT} PUBLIC "./akrypt" )
target_link_libraries( akrypt${LIBAKRYPT_EXT} akrypt-static ${LIBAKRYPT_LIBS} )

# -------------------------------------------------------------------------------------------------- #
enable_testing()

# сборка тестовых примеров
set( EXAMPLES_LIST hello
                   log
                   random
                   randomize
                   random-system
                   oid
                   hash
                   hash-oids
                   sha2
)

# организуем сборку примеров со статической линковкой
if( LIBAKRYPT_STATIC_LIB )
  foreach( programm ${EXAMPLES_LIST} )
     add_executable( example-${programm}${LIBAKRYPT_EXT} examples/example-${programm}.c )
     target_link_libraries( example-${programm}${LIBAKRYPT_EXT} akrypt-static ${LIBAKRYPT_LIBS} )
  endforeach()
endif()

# организуем сборку примеров с динамической линковкой
if( LIBAKRYPT_SHARED_LIB )
  foreach( programm ${EXAMPLES_LIST} )
     add_executable( example-dynamic-${programm}${LIBAKRYPT_EXT} examples/example-${programm}.c )
     target_link_libraries( example-dynamic-${programm}${LIBAKRYPT_EXT} akrypt-shared ${LIBAKRYPT_LIBS} )
  endforeach()
endif()

# -------------------------------------------------------------------------------------------------- #
# теперь примеры, использующие неэкспортируемые функции
set( INTERNAL_EXAMPLES_LIST
                   context-manager-node
                   context-manager
                   #bckey-internal
                   #mac-internal
                   #mac-file
                   #test
                   internal-hash01
                   internal-hash02
                   internal-hash03
                   internal-compress01
)

if( CMAKE_HOST_UNIX )
  foreach( programm ${INTERNAL_EXAMPLES_LIST} )
     add_executable( example-${programm}${LIBAKRYPT_EXT} examples/example-${programm}.c )
     target_link_libraries( example-${programm}${LIBAKRYPT_EXT} akrypt-static ${LIBAKRYPT_LIBS} )
     add_test( NAME example-${programm}${LIBAKRYPT_EXT} COMMAND example-${programm}${LIBAKRYPT_EXT} )
  endforeach()
endif()

# -------------------------------------------------------------------------------------------------- #
# напоследок тестовые примеры для арифметических операций
set( ARITHMETIC_TESTS_LIST
                   mpzn-convert
                   mpzn-arithmetic
                   mpzn-montgomery
                   mpzn-rem
)

if( LIBAKRYPT_GMP_TESTS )
  foreach( programm ${ARITHMETIC_TESTS_LIST} )
     add_executable( example-${programm}${LIBAKRYPT_EXT} examples/example-${programm}.c )
     target_link_libraries( example-${programm}${LIBAKRYPT_EXT} akrypt-static gmp )
     add_test( NAME example-${programm} COMMAND example-${programm}${LIBAKRYPT_EXT} )
  endforeach()
  message("-- Added examples for integer arithmetic")
endif()

# -------------------------------------------------------------------------------------------------- #
if( CMAKE_HOST_UNIX )
  include( MakeDoc )
  include( MakeDist )
endif()
include( MakeInstall )

# -------------------------------------------------------------------------------------------------- #
message("-- Compiler options is ${CMAKE_C_FLAGS}" )

# -------------------------------------------------------------------------------------------------- #
