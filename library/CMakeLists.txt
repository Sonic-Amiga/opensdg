# Unfortunately Windows doesn't have centralized source package management
# like pkg-config
if (MSVC)
  if ("${PROTOBUF_ROOT}" STREQUAL "")
    set(PROTOBUF_ROOT "C:/Program Files/protobuf-c")
  endif ("${PROTOBUF_ROOT}" STREQUAL "")
  set(PROTOBUF_PATH ${PROTOBUF_ROOT}/lib)

  if (STATIC_BUILD)
    set(SODIUM_FLAVOR static)
  else (STATIC_BUILD)
    set(SODIUM_FLAVOR dynamic)
  endif (STATIC_BUILD)
  set(SODIUM_PATH ${SODIUM_ROOT}/${CMAKE_VS_PLATFORM_NAME}/Release/v142/${SODIUM_FLAVOR})

  set(EXTRA_LIBS Ws2_32)
else (MSVC)
  set(EXTRA_LIBS pthread)
endif (MSVC)

# On Armbian 5.85 protoc-gen-c binary is not provided, so we try to use
# protoc-c first. But Windows provides protoc-gen-c, but no protoc-c, so
# we use common Google's frontend
find_program(PROTOC NAMES protoc-c protoc)
if (${PROTOC} STREQUAL "PROTOC-NOTFOUND")
  message(FATAL_ERROR "Protobuf C compiler is required for the build")
endif (${PROTOC} STREQUAL "PROTOC-NOTFOUND")
message("protoc found in ${PROTOC}")

find_library(SODIUM NAMES libsodium sodium PATHS ${SODIUM_PATH})
if (${SODIUM} STREQUAL "SODIUM-NOTFOUND")
  message(FATAL_ERROR "libsodium is required for the build. You may need to specify SODIUM_ROOT.")
endif (${SODIUM} STREQUAL "SODIUM-NOTFOUND")
message("libsodium found in ${SODIUM}")

find_library(PROTOBUF NAMES libprotobuf-c protobuf-c PATHS ${PROTOBUF_PATH})
if (${PROTOBUF} STREQUAL "PROTOBUF-NOTFOUND")
  message(FATAL_ERROR "libprotobuf-c is required for the build")
endif (${PROTOBUF} STREQUAL "PROTOBUF-NOTFOUND")
message("libprotobuf-c found in ${PROTOBUF}")

set(LIBRARY_SOURCES client.c client.h logging.c logging.h
                    tunnel_protocol.c tunnel_protocol.h
					grid.c peer.c control_protocol.h
					socket.c socket.h
					mainloop_events.c mainloop.h utils.c utils.h
					pthread_wrapper.h)
set(PROTOBUF_SOURCES control_protocol.pb-c.c control_protocol.pb-c.h)

if (WIN32)
  set(SYSDEP_SOURCES mainloop_win32.c)
else (WIN32)
  set(SYSDEP_SOURCES mainloop_poll.c)
endif (WIN32)

add_custom_command(OUTPUT ${PROTOBUF_SOURCES}
                   COMMAND ${PROTOC} --c_out=${CMAKE_CURRENT_BINARY_DIR} --proto_path ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/control_protocol.proto
                   DEPENDS control_protocol.proto)

if (STATIC_BUILD)
  add_library(opensdg STATIC ${LIBRARY_SOURCES} ${PROTOBUF_SOURCES} ${SYSDEP_SOURCES} ${PUBLIC_INCLUDE_FILES})
  set_property(TARGET opensdg PROPERTY COMPILE_DEFINITIONS SODIUM_STATIC)
else (STATIC_BUILD)
  add_library(opensdg SHARED ${LIBRARY_SOURCES} ${PROTOBUF_SOURCES} ${SYSDEP_SOURCES} ${PUBLIC_INCLUDE_FILES})
  set_property(TARGET opensdg PROPERTY COMPILE_DEFINITIONS OPENSDG_BUILD)
endif (STATIC_BUILD)
target_include_directories(opensdg PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(opensdg PRIVATE ${SODIUM} ${PROTOBUF} PUBLIC ${EXTRA_LIBS})

if (NOT ${SODIUM_ROOT} STREQUAL "")
  target_include_directories(opensdg PRIVATE ${SODIUM_ROOT}/include)
endif (NOT ${SODIUM_ROOT} STREQUAL "")
if (NOT ${PROTOBUF_ROOT} STREQUAL "")
  target_include_directories(opensdg PRIVATE ${PROTOBUF_ROOT}/include)
endif (NOT ${PROTOBUF_ROOT} STREQUAL "")

install(TARGETS opensdg
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib)
