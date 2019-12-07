# Unfortunately Windows doesn't have centralized source package management
# like pkg-config

set(JNI_SOURCES opensdg_jni.c)
set(JNI_HEADER org_opensdg_OpenSDG.h)

set(JAVA_DIR ${CMAKE_SOURCE_DIR}/java)
file(GLOB_RECURSE JAVA_SOURCES ${JAVA_DIR}/src/*.java)

find_program(JAVAC javac)
if (${JAVAC} STREQUAL "JAVAC-NOTFOUND")
  message("javac not found, Java binding will not be built")
else (${JAVAC} STREQUAL "JAVAC-NOTFOUND")
  message("javac found in ${JAVAC}")

  # FIXME: Currently verified on Windows only
  set(JAVA_HOME $ENV{JAVA_HOME})
  if ("${JAVA_HOME}" STREQUAL "")
    get_filename_component(JAVA_BINDIR ${JAVAC} DIRECTORY)
    set(JAVA_HOME ${JAVA_BINDIR}/..)
  endif ("${JAVA_HOME}" STREQUAL "")

  add_custom_command(OUTPUT ${JNI_HEADER}
                     COMMAND ${JAVAC} -h ${CMAKE_CURRENT_BINARY_DIR} -d ${JAVA_DIR}/target/classes ${JAVA_SOURCES}
                     DEPENDS ${JAVA_SOURCES})
  add_library(opensdg_jni SHARED ${JNI_SOURCES} ${JNI_HEADER} ${PUBLIC_INCLUDE_FILES})
  target_include_directories(opensdg_jni PRIVATE ${JAVA_HOME}/include ${JAVA_HOME}/include/win32 ${CMAKE_CURRENT_BINARY_DIR})
  target_link_libraries(opensdg_jni PUBLIC opensdg)

  if (MSVC AND STATIC_BUILD)
    # Unfortunately we don't have .pdb for static libsodium'
    target_link_options(opensdg_jni PRIVATE "/ignore:4099")
  endif (MSVC AND STATIC_BUILD)

endif (${JAVAC} STREQUAL "JAVAC-NOTFOUND")

