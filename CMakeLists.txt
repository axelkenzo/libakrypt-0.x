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
# cmake -G "MinGW Makefiles" path && make
# -------------------------------------------------------------------------------------------------- #
cmake_minimum_required( VERSION 2.8 )
project( libakrypt )
set( HEAD_VERSION 0 )
set( MAIN_VERSION 4 )
set( MINOR_VERSION 31 )

set( MAJOR_VERSION ${HEAD_VERSION}.${MAIN_VERSION} )
set( FULL_VERSION ${MAJOR_VERSION}.${MINOR_VERSION} )

option( LIBAKRYPT_STATIC_LIB "Build the static library" ON )
option( LIBAKRYPT_SHARED_LIB "Build the shared library" OFF )
option( LIBAKRYPT_GMP_TESTS "Build test programs with libGMP" OFF)
# для включения опции cmake -D LIBAKRYPT_GMP_TESTS=ON path

# -------------------------------------------------------------------------------------------------- #
# описание исходных кодов
set( MAIN_HEADER source/libakrypt.h )
set( HEADERS source/ak_buffer.h
             source/ak_oid.h
             source/ak_hash.h
             source/ak_update.h
             source/ak_random.h
             source/ak_skey.h
             source/ak_parameters.h
             source/ak_tools.h
             source/ak_context_manager.h
             source/ak_mpzn.h
             source/ak_curves.h )
set( SOURCES source/ak_tools.c
             source/ak_buffer.c
             source/ak_oid.c
             source/ak_hash.c
             source/ak_update.c
             source/ak_streebog.c
             source/ak_gosthash.c
             source/ak_random.c
             source/ak_skey.c
             source/ak_bckey.c
             source/ak_magma.c
#             source/ak_kuznetchik.c
             source/ak_context_manager.c
             source/ak_hmac.c
             source/ak_mpzn.c
             source/ak_curves.c
             source/ak_rc6.c )
set( DOCS    doc/libakrypt.dox
             doc/refman_header.in
             doc/refman_footer.in
             doc/Doxyfile.in )
set( CMAKES  cmake/DetectFlags.cmake
             cmake/DetectIntrinsics.cmake
             cmake/FindRelations.cmake
             cmake/MakeDist.cmake
             cmake/MakeDoc.cmake )
set( OTHERS  CMakeLists.txt
             libakrypt.rc.in
             libakrypt.conf
             TODO )

# -------------------------------------------------------------------------------------------------- #
set( CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake ${CMAKE_MODULE_PATH} )
include( DetectFlags )
include( DetectIntrinsics )
include( FindRelations )

# -------------------------------------------------------------------------------------------------- #
# сборка библиотек
include_directories( "./source" )
if( LIBAKRYPT_CONF )
    message("-- Path for libakrypt.conf is ${LIBAKRYPT_CONF}")
    add_compile_options( -DLIBAKRYPT_OPTIONS_PATH="${LIBAKRYPT_CONF}" )
endif()
add_compile_options( -DLIBAKRYPT_VERSION="${FULL_VERSION}" )
#
if( LIBAKRYPT_SHARED_LIB )
  add_library( akrypt-shared SHARED ${MAIN_HEADER} ${SOURCES} )
  set_target_properties( akrypt-shared PROPERTIES VERSION ${MAJOR_VERSION} SOVERSION ${FULL_VERSION} )
  target_link_libraries( akrypt-shared ${PTHREAD_LIB} )
endif()
#
if( LIBAKRYPT_STATIC_LIB )
  add_library( akrypt-static STATIC ${MAIN_HEADER} ${SOURCES} )
  set_target_properties( akrypt-static PROPERTIES VERSION ${MAJOR_VERSION} SOVERSION ${FULL_VERSION} )
endif()

# -------------------------------------------------------------------------------------------------- #
# сборка тестовых примеров
if( LIBAKRYPT_STATIC_LIB )
  set( EXAMPLES_LIST intro
                     log
                     oid
                     oid-magma
                     hash
                     hash-parts
                     hash-update
                     hash-oids
                     random
                     rc6
                     dev-random
                     bckey
                     context-manager
                     hmac-key
                     hmac-key-file
                     key
                     )
  foreach( programm ${EXAMPLES_LIST} )
      # сборка статических примеров
      add_executable( example-${programm}${LIBAKRYPT_EXT} examples/example-${programm}.c )
      target_link_libraries( example-${programm}${LIBAKRYPT_EXT} akrypt-static ${PTHREAD_LIB} )
  endforeach()
endif()

# -------------------------------------------------------------------------------------------------- #
# поиск gmp для отладки и тестирования арифметических операций
if( LIBAKRYPT_GMP_TESTS )
  find_library( GMPLIB gmp )
  if( GMPLIB )
    find_file( GMPLIB_H gmp.h )
    if( GMPLIB_H )
      message("-- Searching libgmp for special arithmetic tests is done")
      set( ARITHMETIC_TESTS_LIST mpzn-convert-to-gmp
                                 mpzn-convert-to-hexstr
                                 mpzn-random-modulo
                                 mpzn-arithmetic
                                 mpzn-rem )
      foreach( programm ${ARITHMETIC_TESTS_LIST} )
         # сборка статических примеров
         add_executable( example-${programm} examples/example-${programm}.c )
         target_link_libraries( example-${programm} akrypt-static ${PTHREAD_LIB} gmp )
      endforeach()
    endif()
  endif()
endif()

# -------------------------------------------------------------------------------------------------- #
# очистка служебной информации из статических примеров
add_custom_target( strip strip --strip-all ${CMAKE_BINARY_DIR}/example-* )

# -------------------------------------------------------------------------------------------------- #
include( MakeDist )
include( MakeDoc )
message("-- Compiler options is ${CMAKE_C_FLAGS}" )

# -------------------------------------------------------------------------------------------------- #
# инсталляция библиотеки (только для UNIX)
if( CMAKE_HOST_UNIX )
  if( LIBAKRYPT_SHARED_LIB )
    install( TARGETS akrypt-shared
             LIBRARY DESTINATION lib
             ARCHIVE DESTINATION lib
           )
  endif()
  if( LIBAKRYPT_STATIC_LIB )
    install( TARGETS akrypt-static
             LIBRARY DESTINATION lib
             ARCHIVE DESTINATION lib
           )
  endif()
  install( FILES ${MAIN_HEADER} DESTINATION include )
  install( FILES libakrypt.conf DESTINATION ${LIBAKRYPT_CONF} )
endif()

# -------------------------------------------------------------------------------------------------- #
