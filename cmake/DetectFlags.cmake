# -------------------------------------------------------------------------------------------------- #
include(CheckCCompilerFlag)

# -------------------------------------------------------------------------------------------------- #
# макросы для поиска флагов
macro( gen_check_name _flag )
     string(REGEX REPLACE "-+|=" "_" _check_name "${_flag}")
     string(REPLACE "," "" _check_name "${_check_name}")
     string(REPLACE "/" "_" _check_name "${_check_name}")
     string(REPLACE ":" "_" _check_name "${_check_name}")
     string(TOUPPER "${_check_name}" _check_name)
     set(_check_name "LIBAKRYPT_HAVE${_check_name}")
endmacro(gen_check_name)

macro( try_append_c_flag _flag _append_to )
     gen_check_name("${_flag}")
     check_c_compiler_flag("${_flag}" ${_check_name})
     if(${_check_name})
       set(${_append_to} "${${_append_to}} ${_flag}")
       string(STRIP "${${_append_to}}" ${_append_to})
     endif()
endmacro( try_append_c_flag )

# -------------------------------------------------------------------------------------------------- #
if( MSVC )
# набор флагов для компиляторов семейства MSVC
  try_append_c_flag( "/Ot" CMAKE_C_FLAGS )
  try_append_c_flag( "/Ob2" CMAKE_C_FLAGS )
  try_append_c_flag( "/Qpar" CMAKE_C_FLAGS )
  try_append_c_flag( "/W3" CMAKE_C_FLAGS )
  try_append_c_flag( "/TC" CMAKE_C_FLAGS )
  try_append_c_flag( "/arch:SSE2" CMAKE_C_FLAGS )
  try_append_c_flag( "/MD" CMAKE_C_FLAGS )
  try_append_c_flag( "/DNDEBUG" CMAKE_C_FLAGS )
else()
  # набор Unix'овых флагов
  try_append_c_flag( "-Wall" CMAKE_C_FLAGS )
  try_append_c_flag( "-pedantic-errors" CMAKE_C_FLAGS )
  try_append_c_flag( "-O3" CMAKE_C_FLAGS )
  try_append_c_flag( "-funroll-loops" CMAKE_C_FLAGS )
  try_append_c_flag( "-march=native" CMAKE_C_FLAGS )
  try_append_c_flag( "-std=c99" CMAKE_C_FLAGS )
  try_append_c_flag( "-pipe" CMAKE_C_FLAGS )
  
  # Исключение для MacOS
  if(NOT ${CMAKE_SYSTEM_NAME} STREQUAL "Darwin")
     try_append_c_flag( "-Wl,--strip-all" CMAKE_EXE_LINKER_FLAGS )
  endif()
endif()

# -------------------------------------------------------------------------------------------------- #
