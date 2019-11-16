# Unfortunately Windows doesn't have centralized source package management
# like pkg-config
if (MSVC)
  if ("${PROTOBUF_ROOT}" STREQUAL "")
    set(PROTOBUF_ROOT "C:/Program Files/protobuf-c")
  endif ("${PROTOBUF_ROOT}" STREQUAL "")
  set(SODIUM_PATH ${SODIUM_ROOT}/${CMAKE_VS_PLATFORM_NAME}/Release/v142/dynamic)
  set(PROTOBUF_PATH ${PROTOBUF_ROOT}/lib)
  set(EXTRA_LIBS Ws2_32)
else (MSVC)
  set(EXTRA_LIBS pthread)
endif (MSVC)

find_program(PROTOC protoc)
if (${PROTOC} STREQUAL "PROTOC-NOTFOUND")
  message(FATAL_ERROR "Google protobuf compiler is required for the build")
endif (${PROTOC} STREQUAL "PROTOC-NOTFOUND")
message("protoc found in ${PROTOC}")

find_library(SODIUM NAMES libsodium sodium PATHS ${SODIUM_PATH})
if (${SODIUM} STREQUAL "SODIUM-NOTFOUND")
  message(FATAL_ERROR "libsodium is required for the build")
endif (${SODIUM} STREQUAL "SODIUM-NOTFOUND")
message("libsodium found in ${SODIUM}")

find_library(PROTOBUF NAMES libprotobuf-c protobuf-c PATHS ${PROTOBUF_PATH})
if (${PROTOBUF} STREQUAL "PROTOBUF-NOTFOUND")
  message(FATAL_ERROR "libprotobuf-c is required for the build")
endif (${PROTOBUF} STREQUAL "PROTOBUF-NOTFOUND")
message("libprotobuf-c found in ${PROTOBUF}")

set(LIBRARY_SOURCES client.c client.h logging.c logging.h
                    protocol.c protocol.h grid.c peer.c
					registry.c registry.h socket.c socket.h
					mainloop.c mainloop.h
					uthash.h pthread_wrapper.h)
set(PROTOBUF_SOURCES protocol.pb-c.c protocol.pb-c.h)

add_custom_command(OUTPUT ${PROTOBUF_SOURCES}
                   COMMAND ${PROTOC} --c_out=${CMAKE_CURRENT_BINARY_DIR} --proto_path ${CMAKE_CURRENT_SOURCE_DIR} protocol.proto
                   DEPENDS protocol.proto) 

add_library(opensdg SHARED ${LIBRARY_SOURCES} ${PROTOBUF_SOURCES} ${PUBLIC_INCLUDE_FILES})
set_property(TARGET opensdg PROPERTY COMPILE_DEFINITIONS OPENSDG_BUILD)
target_include_directories(opensdg PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(opensdg PRIVATE ${SODIUM} ${PROTOBUF} PUBLIC ${EXTRA_LIBS})

if (NOT ${SODIUM_ROOT} STREQUAL "")
  target_include_directories(opensdg PRIVATE ${SODIUM_ROOT}/include)
endif (NOT ${SODIUM_ROOT} STREQUAL "")
if (NOT ${PROTOBUF_ROOT} STREQUAL "")
  target_include_directories(opensdg PRIVATE ${PROTOBUF_ROOT}/include)
endif (NOT ${PROTOBUF_ROOT} STREQUAL "")
