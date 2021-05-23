# -------------------------------------------------------------------------------------------------- #
# Copyright (c) 2014 - 2021 by Axel Kenzo, axelkenzo@mail.ru
#
# CMakeLists.txt
# -------------------------------------------------------------------------------------------------- #
cmake_minimum_required( VERSION 3.2 FATAL_ERROR )

# -------------------------------------------------------------------------------------------------- #
set( HEAD_VERSION 0 )
set( MAIN_VERSION 9 )
set( MINOR_VERSION 4 )
set( MAJOR_VERSION ${HEAD_VERSION}.${MAIN_VERSION} )
set( FULL_VERSION ${MAJOR_VERSION}.${MINOR_VERSION} )

# -------------------------------------------------------------------------------------------------- #
# Формируем название проекта
project( libakrypt C )

# -------------------------------------------------------------------------------------------------- #
# Перечень доступных опций для сборки библиотеки
option( AK_STATIC_LIB "Build the static library" ON )
option( AK_SHARED_LIB "Build the shared library" ON )
option( AK_TESTS_GMP "Build comparison tests for gmp and libakrypt" OFF )

# -------------------------------------------------------------------------------------------------- #
# Перечень опций, которые имеют предустановленные значения и могут изменяться через командную строку
# для linux
#   set( AK_CONFIG_PATH  "/etc" )
#   set( AK_CA_PATH "/usr/share/ca-certificates" )

# -------------------------------------------------------------------------------------------------- #
# Подключаем модули CMake для тонкой настройки параметров сборки
set( CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake ${CMAKE_MODULE_PATH} )
include( DetectFlags )
include( DetectHeaders )
include( DetectIntrinsics )
include( DetectLibraries )

# -------------------------------------------------------------------------------------------------- #
# Вырабатываем заголовочный файл (в каталоге сборки)
configure_file( ${CMAKE_SOURCE_DIR}/source/libakrypt-base.h.in ${CMAKE_BINARY_DIR}/libakrypt-base.h @ONLY )
message("-- Generation of libakrypt-base.h is done")

# -------------------------------------------------------------------------------------------------- #
# Определяем базовое множество исходных текстов библиотеки
set( MAIN_HEADERS ${CMAKE_BINARY_DIR}/libakrypt-base.h source/libakrypt.h )

# -------------------------------------------------------------------------------------------------- #
set( AKBASE_SOURCES
   source/ak_tools.c
   source/ak_ini.c
   source/ak_list.c
   source/ak_file.c
   source/ak_base64.c
  )

# -------------------------------------------------------------------------------------------------- #
# Добавляем исходные тексты для криптобиблиотеки
set( AKRYPT_SOURCES
   source/libakrypt-internal.h
   source/ak_options.c
   source/ak_libakrypt.c
   source/ak_oid.c
   source/ak_random.c
   source/ak_gf2n.c
   source/ak_mpzn.c
   source/ak_128.c
   source/ak_curves.c
   source/ak_parameters.c
   source/ak_mac.c
   source/ak_hash.c
   source/ak_skey.c
   source/ak_hmac.c
   source/ak_bckey.c
   source/ak_cmac.c
   source/ak_magma.c
   source/ak_kuznechik.c
   source/ak_acpkm.c
   source/ak_mgm.c
   source/ak_xts.c
   source/ak_asn1.c
   source/ak_sign.c
   source/ak_asn1_keys.c
   source/ak_asn1_cert.c
   source/ak_blom.c
)

# -------------------------------------------------------------------------------------------------- #
# Проверка архитектуры
include( TestBigEndian )
TEST_BIG_ENDIAN( IS_BIG_ENDIAN )
if( IS_BIG_ENDIAN )
  set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DAK_BIG_ENDIAN" )
else()
  set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DAK_LITTLE_ENDIAN" )
endif()
message("-- Used compile flags ${CMAKE_C_FLAGS}")

# -------------------------------------------------------------------------------------------------- #
# Определяем место хранения файла с  настройками библиотеки
# -------------------------------------------------------------------------------------------------- #
if( AK_CONFIG_PATH )
else()
  if( CMAKE_HOST_UNIX )
    set( AK_CONFIG_PATH "etc" )
  endif()
  if( WIN32 )
    set( AK_CONFIG_PATH "C:\\\\Program Files\\\\Akrypt" )
  endif()
endif()
message("-- Path for libakrypt.conf is ${AK_CONFIG_PATH}")

# -------------------------------------------------------------------------------------------------- #
# Определяем место хранения доверенных сертификатов библиотеки
# -------------------------------------------------------------------------------------------------- #
if( AK_CA_PATH )
else()
  if( CMAKE_HOST_UNIX )
    set( AK_CA_PATH "usr/share/ca-certificates/libakrypt" )
  endif()
  if( WIN32 )
    set( AK_CA_PATH "C:\\\\Program Files\\\\Akrypt\\\\ca-certificates" )
  endif()
endif()
message("-- Path for ca-certificates is ${AK_CA_PATH}")

# -------------------------------------------------------------------------------------------------- #
# Определем процедуры сборки библиотек - статической или динамической
include_directories( "source" )
include_directories( ${CMAKE_BINARY_DIR} )
add_compile_options( -DLIBAKRYPT_OPTIONS_PATH="${AK_CONFIG_PATH}" )
add_compile_options( -DLIBAKRYPT_VERSION="${FULL_VERSION}" )
add_compile_options( -DLIBAKRYPT_COMPILER_NAME="${CMAKE_C_COMPILER}" )
add_compile_options( -DLIBAKRYPT_COMPILER_VERSION="${CMAKE_C_COMPILER_VERSION}" )
add_compile_options( -DLIBAKRYPT_CA_PATH="${AK_CA_PATH}" )

if( AK_SHARED_LIB )
  add_library( akbase-shared SHARED ${MAIN_HEADERS} ${AKBASE_SOURCES} )
  set_target_properties( akbase-shared PROPERTIES VERSION ${MAJOR_VERSION} SOVERSION ${FULL_VERSION} )
  set_target_properties( akbase-shared PROPERTIES OUTPUT_NAME akrypt-base CLEAN_DIRECT_CUSTOM 1 )
  target_link_libraries( akbase-shared ${LIBAKRYPT_LIBS} )
  message( "-- Building libakrypt-base: shared library" )

  add_library( akrypt-shared SHARED ${MAIN_HEADERS} ${AKRYPT_SOURCES} )
  set_target_properties( akrypt-shared PROPERTIES VERSION ${MAJOR_VERSION} SOVERSION ${FULL_VERSION} )
  set_target_properties( akrypt-shared PROPERTIES OUTPUT_NAME akrypt CLEAN_DIRECT_CUSTOM 1 )
  target_link_libraries( akrypt-shared akbase-shared ${LIBAKRYPT_LIBS} )
  message( "-- Building libakrypt: shared library" )
endif()

#
if( AK_STATIC_LIB )
  add_library( akbase-static STATIC ${MAIN_HEADERS} ${AKBASE_SOURCES} )
  set_target_properties( akbase-static PROPERTIES OUTPUT_NAME akrypt-base CLEAN_DIRECT_CUSTOM 1 )
  target_link_libraries( akbase-static ${LIBAKRYPT_LIBS} )
  message( "-- Building libakrypt-base: static library" )

  add_library( akrypt-static STATIC ${MAIN_HEADERS} ${AKRYPT_SOURCES} )
  set_target_properties( akrypt-static PROPERTIES OUTPUT_NAME akrypt CLEAN_DIRECT_CUSTOM 1 )
  target_link_libraries( akrypt-static akbase-static ${LIBAKRYPT_LIBS} )
  message( "-- Building libakrypt: shared library" )
endif()

# -------------------------------------------------------------------------------------------------- #
# Сборка примеров, иллюстрирующих работу базовой библиотеки
# -------------------------------------------------------------------------------------------------- #
set( EXAMPLES_LIST
     log
     ini
     file
   )

foreach( programm ${EXAMPLES_LIST} )
  if( AK_STATIC_LIB )
    add_executable( example-${programm} examples/example-${programm}.c )
    target_link_libraries( example-${programm} akbase-static ${LIBAKRYPT_LIBS} )
  endif()
  if( AK_SHARED_LIB )
    add_executable( example-shared-${programm} examples/example-${programm}.c )
    target_link_libraries( example-shared-${programm} akbase-shared ${LIBAKRYPT_LIBS} )
  endif()
endforeach()

# -------------------------------------------------------------------------------------------------- #
# Сборка тестовых примеров, проверяющих корректность элементарных арифметических операций
set ( ARITHMETIC_TESTS_LIST
      random01
      gf2n
      mgm01
      xtsmac01
      asn1-build
      asn1-parse
      sign01
      asn1-keys
      asn1-cert
      blom-keys
    )

if( AK_TESTS_GMP )
  set( ARITHMETIC_TESTS_LIST ${ARITHMETIC_TESTS_LIST}
       mpzn-arithmetic
       mpzn-convert
       mpzn-montgomery
       mpzn-rem
     )
endif()

enable_testing()
foreach( programm ${ARITHMETIC_TESTS_LIST} )
  add_executable( test-${programm} examples/test-${programm}.c )
  target_link_libraries( test-${programm} akrypt-static akbase-static ${LIBAKRYPT_LIBS} )
  add_test( NAME test-${programm} COMMAND test-${programm} )
endforeach()
message("-- Added tests (now \"make test\" enabled): [ ${ARITHMETIC_TESTS_LIST} ]" )

# -------------------------------------------------------------------------------------------------- #
# Сборка большого примера для функций криптобиблиотеки -- утилиты aktool
# -------------------------------------------------------------------------------------------------- #
set( AKTOOL_SOURCES
     aktool/aktool.c
     aktool/aktool_show.c
     aktool/aktool_test.c
     aktool/aktool_asn1.c
     aktool/aktool_key.c
     aktool/aktool_icode.c
     aktool/aktool_encrypt.c
   )
set( AKTOOL_FILES
     aktool/aktool.h
     aktool/getopt.h
     aktool/getopt.c
   )

# -------------------------------------------------------------------------------------------------- #
if( AK_HAVE_GETOPT_H )
else()
  set( AKTOOL_SOURCES ${AKTOOL_SOURCES} aktool/getopt.c )
endif()
message("-- Sources for aktool: [ ${AKTOOL_SOURCES} ]" )

find_path( AK_HAVE_LIBINTL_H NAMES libintl.h )
if( AK_HAVE_LIBINTL_H )
  include_directories( ${AK_HAVE_LIBINTL_H} )
  message("-- Additional header for aktool is libintl.h" )
endif()

add_executable( aktool ${AKTOOL_SOURCES} )
target_include_directories( aktool PUBLIC "aktool" )

find_library( LIBINTL_LIB intl )
if( LIBINTL_LIB )
  set( LIBAKRYPT_LIBS ${LIBAKRYPT_LIBS} ${LIBINTL_LIB} )
endif()
find_library( LIBICONV_LIB iconv )
if( LIBICONV_LIB )
  set( LIBAKRYPT_LIBS ${LIBAKRYPT_LIBS} ${LIBICONV_LIB} )
endif()

if( LIBAKRYPT_LIBS )
  message("-- Additional libraries for aktool is ${LIBAKRYPT_LIBS}")
endif()
target_link_libraries( aktool akrypt-static akbase-static ${LIBAKRYPT_LIBS} )

# -------------------------------------------------------------------------------------------------- #
# Сборка документации и завершающие настройки
 include( MakeDoc )
 set( LIBAKRYPT_DOCUMENTATION
      ${CMAKE_SOURCE_DIR}/LICENSE
      ${CMAKE_SOURCE_DIR}/Changelog.md
 )
 # теперь файлы с документацией не включаются в перечень инсталлируемых файлов по-умолчанию
 # set( LIBAKRYPT_GENERATED_DOCUMENTATION
 #    ${CMAKE_BINARY_DIR}/libakrypt-base-doc-${FULL_VERSION}.pdf
 #    ${CMAKE_BINARY_DIR}/libakrypt-doc-${FULL_VERSION}.pdf
 #   )

# -------------------------------------------------------------------------------------------------- #
# инсталляция библиотеки (только для UNIX)
if( CMAKE_HOST_UNIX )
  if( AK_STATIC_LIB )
    install( TARGETS akbase-static LIBRARY DESTINATION lib ARCHIVE DESTINATION lib )
    install( TARGETS akrypt-static LIBRARY DESTINATION lib ARCHIVE DESTINATION lib )
  endif()

  if( AK_SHARED_LIB )
    install( TARGETS akbase-shared LIBRARY DESTINATION lib ARCHIVE DESTINATION lib )
    install( TARGETS akrypt-shared LIBRARY DESTINATION lib ARCHIVE DESTINATION lib )
  endif()

  install( TARGETS aktool DESTINATION bin )

  install( FILES ${CMAKE_SOURCE_DIR}/libakrypt.conf DESTINATION ${AK_CONFIG_PATH} )
  install( FILES ${MAIN_HEADERS} DESTINATION include )
  install( FILES ${LIBAKRYPT_DOCUMENTATION} DESTINATION share/doc/libakrypt )
  if( GZIP )
    install( FILES ${CMAKE_SOURCE_DIR}/aktool/aktool.1.gz DESTINATION share/man/ru/man1 )
  else()
    install( FILES ${CMAKE_SOURCE_DIR}/aktool/aktool.1 DESTINATION share/man/ru/man1 )
  endif()
  # Этого файла сейчас нет в репозитории
  # install( FILES ${CMAKE_SOURCE_DIR}/cert/ca-libakrypt.crt DESTINATION ${AK_CA_PATH} )

# деинсталляция
# sudo xargs rm < install_manifest.txt

endif()

# -------------------------------------------------------------------------------------------------- #
# настройка пакета для дистрибуции
set( CPACK_GENERATOR "DEB" )
set( CPACK_SOURCE_GENERATOR "TBZ2")
set( CPACK_SOURCE_IGNORE_FILES
  \\.git/
  .gitignore
  TAGS
  "CMakeLists.txt.user*"
  "scratch*"
)

# в зависимостях можно указать в явном виде стандартную библиотеку языка Си,
# но она и так входит в перечень
set( CPACK_DEBIAN_PACKAGE_DEPENDS "libc-bin" )
set( CPACK_PACKAGE_VERSION_MAJOR ${HEAD_VERSION} )
set( CPACK_PACKAGE_VERSION_MINOR ${MAIN_VERSION} )
set( CPACK_PACKAGE_VERSION_PATCH ${MINOR_VERSION} )

set( CPACK_DEBIAN_PACKAGE_MAINTAINER "Axel Kenzo") #required
set( CPACK_PACKAGE_VENDOR "Axel Kenzo & The Company Of Belles Lettres")
set( CPACK_PACKAGE_FILE_NAME ${CMAKE_PROJECT_NAME}-${FULL_VERSION}-${CMAKE_SYSTEM_PROCESSOR} )
set( CPACK_SOURCE_PACKAGE_FILE_NAME "${CMAKE_PROJECT_NAME}-${FULL_VERSION}" )
set( CPACK_STRIP_FILES TRUE )
set( CPACK_PACKAGE_DESCRIPTION
     "Библиотека, реализующая российские криптографические механизмы в пространстве пользователя" )
set(CPACK_VERBATIM_VARIABLES YES)
   
include( CPack )

# -------------------------------------------------------------------------------------------------- #
#                                                                                    CMakeLists.txt
# -------------------------------------------------------------------------------------------------- #
