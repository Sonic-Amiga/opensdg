find_library(SODIUM libsodium PATHS ${SODIUM_ROOT}/${CMAKE_VS_PLATFORM_NAME}/Release/v142/dynamic)
if (${SODIUM} STREQUAL "SODIUM-NOTFOUND")
  message(FATAL_ERROR "libsodium is required for the build")
endif (${SODIUM} STREQUAL "SODIUM-NOTFOUND")

message("libsodium found in ${SODIUM}")

set(LIBRARY_SOURCES client.c client.h logging.c logging.h protocol.c protocol.h)
add_library(opensdg SHARED ${LIBRARY_SOURCES})
set_property(TARGET opensdg PROPERTY COMPILE_DEFINITIONS OPENSDG_BUILD)
target_include_directories(opensdg PRIVATE ${SODIUM_ROOT}/include)
target_link_directories(opensdg PRIVATE ${SODIUM_ROOT}/${CMAKE_VS_PLATFORM_NAME}/$(Configuration)/v142/dynamic)
target_link_libraries(opensdg PRIVATE libsodium PUBLIC Ws2_32)