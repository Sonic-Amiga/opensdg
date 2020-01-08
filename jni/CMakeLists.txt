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

  if (UNIX)
    execute_process(COMMAND readlink -f ${JAVAC} OUTPUT_VARIABLE JAVAC_REALPATH)
    set(JNI_SYS linux)
  else (UNIX)
    set(JAVAC_REALPATH ${JAVAC})
    set(JNI_SYS win32)
  endif (UNIX)

  set(JAVA_HOME $ENV{JAVA_HOME})
  if ("${JAVA_HOME}" STREQUAL "")
    get_filename_component(JAVA_BINDIR ${JAVAC_REALPATH} DIRECTORY)
    set(JAVA_HOME ${JAVA_BINDIR}/..)
    message("Detected JAVA_HOME ${JAVA_HOME}")
  endif ("${JAVA_HOME}" STREQUAL "")

  add_custom_command(OUTPUT ${JNI_HEADER}
                     COMMAND ${JAVAC} -h ${CMAKE_CURRENT_BINARY_DIR} -d ${JAVA_DIR}/target/classes ${JAVA_SOURCES}
                     DEPENDS ${JAVA_SOURCES})
  add_library(opensdg_jni SHARED ${JNI_SOURCES} ${JNI_HEADER} ${PUBLIC_INCLUDE_FILES})
  target_include_directories(opensdg_jni PRIVATE ${JAVA_HOME}/include ${JAVA_HOME}/include/${JNI_SYS} ${CMAKE_CURRENT_BINARY_DIR})
  target_link_libraries(opensdg_jni PUBLIC opensdg)

  # javac has also created .class files, so let's build a JAR too
  add_custom_target(opensdg_jar ALL jar -cvf ${JAVA_DIR}/OpenSDG.jar org WORKING_DIRECTORY ${JAVA_DIR}/target/classes)
  add_dependencies(opensdg_jar opensdg_jni)

  if (MSVC AND STATIC_BUILD)
    # Unfortunately we don't have .pdb for static libsodium'
    target_link_options(opensdg_jni PRIVATE "/ignore:4099")
  endif (MSVC AND STATIC_BUILD)

  install(TARGETS opensdg_jni
          LIBRARY DESTINATION lib
          ARCHIVE DESTINATION lib)


endif (${JAVAC} STREQUAL "JAVAC-NOTFOUND")

