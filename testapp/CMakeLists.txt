set(TESTAPP_SOURCES main.c)
add_executable(opensdg_test ${TESTAPP_SOURCES})
target_link_libraries(opensdg_test PUBLIC opensdg pthread)

if (NOT MSVC)
  target_link_libraries(opensdg_test PUBLIC pthread)
endif (NOT MSVC)

