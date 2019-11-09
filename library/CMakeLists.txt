# Unfortunately Windows doesn't have centralized source package management
# like pkg-config
if (NOT ${CMAKE_VS_PLATFORM_NAME} STREQUAL "")
  set(SODIUM_PATH ${SODIUM_ROOT}/${CMAKE_VS_PLATFORM_NAME}/Release/v142/dynamic)
  set(EXTRA_LIBS Ws2_32)
endif (NOT ${CMAKE_VS_PLATFORM_NAME} STREQUAL "")

find_library(SODIUM NAMES libsodium sodium PATHS ${SODIUM_PATH})
if (${SODIUM} STREQUAL "SODIUM-NOTFOUND")
  message(FATAL_ERROR "libsodium is required for the build")
endif (${SODIUM} STREQUAL "SODIUM-NOTFOUND")
message("libsodium found in ${SODIUM}")

find_library(PROTOBUF NAMES libprotobuf-c protobuf-c)
if (${PROTOBUF} STREQUAL "PROTOBUF-NOTFOUND")
  message(FATAL_ERROR "libprotobuf-c is required for the build")
endif (${PROTOBUF} STREQUAL "PROTOBUF-NOTFOUND")
message("libprotobuf-c found in ${PROTOBUF}")

set(LIBRARY_SOURCES client.c client.h logging.c logging.h protocol.c protocol.h)
set(PROTOBUF_SOURCES protocol.pb-c.c protocol.pb-c.h)

add_custom_command(OUTPUT ${PROTOBUF_SOURCES}
                   COMMAND protoc-c --c_out=${CMAKE_CURRENT_BINARY_DIR} --proto_path ${CMAKE_CURRENT_SOURCE_DIR} protocol.proto
                   DEPENDS protocol.proto) 

add_library(opensdg SHARED ${LIBRARY_SOURCES} ${PROTOBUF_SOURCES})
set_property(TARGET opensdg PROPERTY COMPILE_DEFINITIONS OPENSDG_BUILD)
target_include_directories(opensdg PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(opensdg PRIVATE ${SODIUM} ${PROTOBUF} PUBLIC ${EXTRA_LIBS})

if (NOT ${SODIUM_ROOT} STREQUAL "")
  target_include_directories(opensdg PRIVATE ${SODIUM_ROOT}/include)
endif (NOT ${SODIUM_ROOT} STREQUAL "")

