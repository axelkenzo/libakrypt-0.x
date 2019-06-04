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
project( libakrypt C )

set( HEAD_VERSION 0 )
set( MAIN_VERSION 7 )
set( MINOR_VERSION 13 )

set( MAJOR_VERSION ${HEAD_VERSION}.${MAIN_VERSION} )
set( FULL_VERSION ${MAJOR_VERSION}.${MINOR_VERSION} )

# для включения опции: cmake -D LIBAKRYPT_GMP_TESTS=ON path
option( LIBAKRYPT_STATIC_LIB "Build the static library" ON )
option( LIBAKRYPT_SHARED_LIB "Build the shared library" OFF )
option( LIBAKRYPT_INTERNAL_TESTS "Build collection of internal tests using non-export functions" OFF )
option( LIBAKRYPT_GMP_TESTS "Build comparison tests for gmp and libakrypt" OFF )
option( LIBAKRYPT_HTML_DOC "Build documentation in HTML format" OFF )
option( LIBAKRYPT_PDF_DOC "Build documentation in PDF format" OFF )
option( LIBAKRYPT_CRYPTO_FUNCTIONS "Build library with crypto functions" ON )
option( LIBAKRYPT_CONST_CRYPTO_PARAMS "Build library with const values of crypto parameters" OFF )
option( LIBAKRYPT_NETWORK "Build library with network communications support" OFF )
option( LIBAKRYPT_FIOT "Build library with FIOT protocol support" OFF )
option( LIBAKRYPT_TLS_13 "Build library with TLS 1.3 protocol support" OFF )
option( LIBAKRYPT_AKRYPT "Build console akrypt application" OFF )
option( LIBAKRYPT_PKCS_15_CONTAINER "Build library with PKCS#15 container generating and parsing functions" ON )

# -------------------------------------------------------------------------------------------------- #
if( LIBAKRYPT_FIOT )
  set( LIBAKRYPT_CRYPTO_FUNCTIONS ON )
  set( LIBAKRYPT_NETWORK ON )
endif()
if( LIBAKRYPT_TLS_13 )
 # в настоящее время реализация протокола отсутствует
 # set( LIBAKRYPT_CRYPTO_FUNCTIONS ON )
 # set( LIBAKRYPT_NETWORK ON )
endif()
if( LIBAKRYPT_AKRYPT )
  set( LIBAKRYPT_CRYPTO_FUNCTIONS ON )
endif()

# -------------------------------------------------------------------------------------------------- #
# подключаем модули CMake для тонкой настройки параметров сборки
set( CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake ${CMAKE_MODULE_PATH} )
include( DetectFlags )
include( DetectHeaders )
include( DetectLibraries )
include( DetectIntrinsics )

# -------------------------------------------------------------------------------------------------- #
# множество исходных текстов библиотеки и вспомогательных файлов
set( MAIN_HEADER    source/libakrypt.h )

set( HEADERS        source/ak_tools.h
                    source/ak_buffer.h
                    source/ak_oid.h
                    source/ak_random.h
                    source/ak_mpzn.h
                    source/ak_curves.h
                    source/ak_parameters.h
                    source/ak_gf2n.h
                    source/ak_network.h
)

set( SOURCES        source/ak_tools.c
                    source/ak_buffer.c
                    source/ak_oid.c
                    source/ak_mpzn.c
                    source/ak_curves.c
                    source/ak_random.c
                    source/ak_gf2n.c
                    source/ak_libakrypt.c
)

# -------------------------------------------------------------------------------------------------- #
if( LIBAKRYPT_CRYPTO_FUNCTIONS )
  set( HEADERS      ${HEADERS}
                    source/ak_hash.h
                    source/ak_skey.h
                    source/ak_hmac.h
                    source/ak_mac.h
                    source/ak_context_manager.h
                    source/ak_sign.h
                    source/ak_bckey.h
                    source/ak_omac.h
                    source/ak_mgm.h
  )
  set( SOURCES      ${SOURCES}
                    source/ak_hash.c
                    source/ak_streebog.c
                    source/ak_hashrnd.c
                    source/ak_skey.c
                    source/ak_hmac.c
                    source/ak_mac.c
                    source/ak_context_manager.c
                    source/ak_sign.c
                    source/ak_bckey.c
                    source/ak_kuznechik.c
                    source/ak_magma.c
                    source/ak_omac.c
                    source/ak_mgm.c
                    source/ak_acpkm.c
  )
  add_compile_options( -DLIBAKRYPT_CRYPTO_FUNCTIONS=ON )  
  if( LIBAKRYPT_HAVE_SYSUN )
    set( SOURCES    ${SOURCES}
                    source/ak_udsrnd.c )
  endif()
  if( LIBAKRYPT_HAVE_WINDOWS )
    set( SOURCES    ${SOURCES}
                    source/ak_winrnd.c )
  endif()
endif()

# -------------------------------------------------------------------------------------------------- #
if( LIBAKRYPT_AKRYPT )
  set( AKRYPT_SOURCES
                    akrypt/akrypt.c
                    akrypt/akrypt_show.c
                    akrypt/akrypt_hash.c )
  set( AKRYPT_FILES
                    akrypt/akrypt.h
                    akrypt/akrypt.po
                    akrypt/getopt.h
                    akrypt/getopt.c
                    akrypt/Readme.md )
endif()

# -------------------------------------------------------------------------------------------------- #
if( LIBAKRYPT_NETWORK )
  set( HEADERS      ${HEADERS}
                    source/ak_network.h
  )
  set( SOURCES      ${SOURCES}
                    source/ak_network.c
                    )
  add_compile_options( -DLIBAKRYPT_NETWORK=ON )
endif()

# -------------------------------------------------------------------------------------------------- #
if( LIBAKRYPT_FIOT )
  set( HEADERS      ${HEADERS}
                    source/ak_fiot.h
  )
  set( SOURCES      ${SOURCES}
                    source/ak_fiot.c
                    source/ak_fiot_tlp.c
                    source/ak_fiot_kgp.c
  )
  add_compile_options( -DLIBAKRYPT_FIOT=ON )
endif()

# -------------------------------------------------------------------------------------------------- #
if( LIBAKRYPT_PKCS_15_CONTAINER )
  set( HEADERS      ${HEADERS}
          source/pkcs_15_cryptographic_token/ak_asn_codec.h
          source/pkcs_15_cryptographic_token/kc_includes.h
          source/pkcs_15_cryptographic_token/ak_pkcs_15_token_manager.h
          source/pkcs_15_cryptographic_token/ak_pkcs_15_algs_prms.h
          source/pkcs_15_cryptographic_token/ak_pkcs_15_common_types.h
          source/pkcs_15_cryptographic_token/ak_pkcs_15_token.h
          source/pkcs_15_cryptographic_token/ak_pkcs_15_gost_secret_key.h
          source/pkcs_15_cryptographic_token/ak_pointer_server.h
          )
  set( SOURCES      ${SOURCES}
          source/pkcs_15_cryptographic_token/ak_asn_read.c
          source/pkcs_15_cryptographic_token/ak_asn_write.c
          source/pkcs_15_cryptographic_token/ak_pkcs_15_token_manager.c
          source/pkcs_15_cryptographic_token/ak_pkcs_15_common_types.c
          source/pkcs_15_cryptographic_token/ak_pkcs_15_token.c
          source/pkcs_15_cryptographic_token/ak_pkcs_15_gost_secret_key.c
          source/pkcs_15_cryptographic_token/ak_pointer_server.c
          )
  add_compile_options( -DLIBAKRYPT_PKCS_15_CONTAINER=ON )
endif()

# -------------------------------------------------------------------------------------------------- #
set( CMAKES         cmake/DetectFlags.cmake
                    cmake/DetectHeaders.cmake
                    cmake/DetectIntrinsics.cmake
                    cmake/DetectLibraries.cmake
                    cmake/MakeDist.cmake
                    cmake/MakeDoc.cmake
                    cmake/MakeInstall.cmake
)
set( DOCS           doc/00-introduction.md
                    doc/01-install-guide.md
                    doc/02-primciples.md
                    doc/Doxyfile.in
                    doc/refman_footer.in
                    doc/refman_header.in
)
set( OTHERS         CMakeLists.txt
                    Readme.md
                    Changelog.md
                    libakrypt.conf
                    libakrypt.rc.in
                    LICENSE
)

# -------------------------------------------------------------------------------------------------- #
# определяемся с местом хранения файла с конфигурацией библиотеки
if( LIBAKRYPT_CONF )
else()
  if( CMAKE_HOST_UNIX )
    set( LIBAKRYPT_CONF "/etc" )
  endif()
  if( WIN32 )
    set( LIBAKRYPT_CONF "C:\\\\Program Files\\\\Akrypt" )
  endif()
endif()

# -------------------------------------------------------------------------------------------------- #
if( LIBAKRYPT_CONST_CRYPTO_PARAMS )
  add_compile_options( -DLIBAKRYPT_CONST_CRYPTO_PARAMS=ON )
endif()

# -------------------------------------------------------------------------------------------------- #
# сборка библиотек - статической и, если нужно, динамической
include_directories( "source" )
message("-- Path for libakrypt.conf is ${LIBAKRYPT_CONF}")
add_compile_options( -DLIBAKRYPT_OPTIONS_PATH="${LIBAKRYPT_CONF}" )
add_compile_options( -DLIBAKRYPT_VERSION="${FULL_VERSION}" )
#
if( LIBAKRYPT_SHARED_LIB )
  add_library( akrypt-shared SHARED ${MAIN_HEADER} ${SOURCES} ${ASN1_SOURCES} )
  set_target_properties( akrypt-shared PROPERTIES VERSION ${MAJOR_VERSION} SOVERSION ${FULL_VERSION} )
  target_link_libraries( akrypt-shared ${LIBAKRYPT_LIBS} )
endif()
#
if( LIBAKRYPT_STATIC_LIB )
  add_library( akrypt-static STATIC ${MAIN_HEADER} ${SOURCES} ${ASN1_SOURCES} )
  set_target_properties( akrypt-static PROPERTIES VERSION ${MAJOR_VERSION} SOVERSION ${FULL_VERSION} )
endif()

# -------------------------------------------------------------------------------------------------- #
message("-- Compiler options is ${CMAKE_C_FLAGS}" )
if( LIBAKRYPT_LIBS )
  message("-- Additional libraries is ${LIBAKRYPT_LIBS}" )
endif()

# -------------------------------------------------------------------------------------------------- #
# сборка консольной утилиты для работы с функциями библиотеки
if( LIBAKRYPT_AKRYPT )
  if( LIBAKRYPT_HAVE_GETOPT )
  else()
    set( AKRYPT_SOURCES ${AKRYPT_SOURCES} akrypt/getopt.c )
  endif()
  if( LIBAKRYPT_STATIC_LIB )
    add_executable( akrypt${LIBAKRYPT_EXT} ${AKRYPT_SOURCES} )
    target_include_directories( akrypt${LIBAKRYPT_EXT} PUBLIC "akrypt" )
    target_link_libraries( akrypt${LIBAKRYPT_EXT} akrypt-static ${LIBAKRYPT_LIBS} )
  endif()
endif()

# -------------------------------------------------------------------------------------------------- #
# тестовые примеры для арифметических операций
set( ARITHMETIC_TESTS_LIST
                 mpzn-convert
                 mpzn-arithmetic
                 mpzn-montgomery
                 mpzn-rem
)

if( LIBAKRYPT_GMP_TESTS )
  set( ARITHMETIC_TESTS_LIST ${ARITHMETIC_TESTS_LIST}
                 mpzn-password
  )
  enable_testing()
  if( LIBAKRYPT_STATIC_LIB )
    foreach( programm ${ARITHMETIC_TESTS_LIST} )
       add_executable( test-${programm}${LIBAKRYPT_EXT} tests/test-${programm}.c )
       target_link_libraries( test-${programm}${LIBAKRYPT_EXT} akrypt-static gmp )
       add_test( NAME test-${programm} COMMAND test-${programm}${LIBAKRYPT_EXT} )
    endforeach()
  endif()
  message("-- Added tests for integer arithmetic and comparizon with libgmp (now \"make test\" enabled)")
endif()

# -------------------------------------------------------------------------------------------------- #
# сборка примеров, иллюстрирующих работу с внешним интерфейсом библиотеки
set( EXAMPLES_LIST hello
                   log
                   buffer
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
set( INTERNAL_TEST_LIST
                 internal-random01
                 internal-oid01
                 internal-oid02
                 internal-mpzn01
)
if( LIBAKRYPT_CRYPTO_FUNCTIONS )
  set( INTERNAL_TEST_LIST ${INTERNAL_TEST_LIST}
                 internal-hash01
                 internal-hash02
                 internal-hash03
                 internal-oid03
                 internal-random02
                 internal-sign01
                 internal-sign02
                 internal-bckey01
                 internal-bckey01a
                 internal-bckey02
                 internal-bckey02-magma
                 internal-bckey03
                 internal-bckey05
                 internal-mac01
                 internal-mgm01
                 internal-mgm02
                 internal-mgm03
  )
  set( INTERNAL_TEST_LIST_EXAMPLES # эти программы компилируются, но не вызываются
                                   # при запуске make test
                 internal-bckey04
                 internal-mgm04
  )
  if( LIBAKRYPT_HAVE_SYSUN )
    set( INTERNAL_TEST_LIST_EXAMPLES
                 ${INTERNAL_TEST_LIST_EXAMPLES}
                 internal-random03 )
  endif()
endif()
if( LIBAKRYPT_FIOT )
  set( INTERNAL_FIOT_TEST_LIST
                 internal-fiot-algconst
                 internal-fiot-context
                 internal-fiot-echo-client
  )
  if( UNIX )
    set( INTERNAL_FIOT_TEST_LIST
                 ${INTERNAL_FIOT_TEST_LIST}
                 internal-fiot-echo-server
    )
  endif()
endif()

if( LIBAKRYPT_PKCS_15_CONTAINER )
  set( INTERNAL_TEST_LIST ${INTERNAL_TEST_LIST}
          internal-pkcs-15-container
          )
endif()

# -------------------------------------------------------------------------------------------------- #
if( LIBAKRYPT_INTERNAL_TESTS )
  enable_testing()

  # добавляем примеры в случае сборки статической библиотеки
  if( LIBAKRYPT_STATIC_LIB )
    foreach( programm ${INTERNAL_TEST_LIST} )
       add_executable( test-${programm}${LIBAKRYPT_EXT} tests/test-${programm}.c )
       target_link_libraries( test-${programm}${LIBAKRYPT_EXT} akrypt-static ${LIBAKRYPT_LIBS} )
       add_test( NAME test-${programm}${LIBAKRYPT_EXT} COMMAND test-${programm}${LIBAKRYPT_EXT} )
    endforeach()
    # компилируемые тесты, не попадающие в вызов команды make test
    foreach( programm ${INTERNAL_TEST_LIST_EXAMPLES} )
       add_executable( test-${programm}${LIBAKRYPT_EXT} tests/test-${programm}.c )
       target_link_libraries( test-${programm}${LIBAKRYPT_EXT} akrypt-static ${LIBAKRYPT_LIBS} )
    endforeach()
  endif()
  message("-- Added tests for internal functions (now \"make test\" enabled)")

  # добавляем примеры для тестирования протокольной части (командой make test не затрагиваются)
  if( LIBAKRYPT_STATIC_LIB )
    foreach( programm ${INTERNAL_FIOT_TEST_LIST} )
       add_executable( test-${programm}${LIBAKRYPT_EXT} tests/test-${programm}.c )
       target_link_libraries( test-${programm}${LIBAKRYPT_EXT} akrypt-static ${LIBAKRYPT_LIBS} )
    endforeach()
  endif()

endif()

# -------------------------------------------------------------------------------------------------- #
if( CMAKE_HOST_UNIX )
  include( MakeDoc )
  include( MakeInstall )
  include( MakeDist )
endif()
