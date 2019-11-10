set(TESTAPP_SOURCES main.c pthread_wrapper.h)
add_executable(opensdg_test ${TESTAPP_SOURCES})
target_link_libraries(opensdg_test PUBLIC opensdg)

if (MSVC)
  add_custom_command(TARGET opensdg_test POST_BUILD
                     COMMAND ${CMAKE_COMMAND} -E copy_if_different
                     $<TARGET_FILE_DIR:opensdg>/opensdg.dll
                     $<TARGET_FILE_DIR:opensdg_test>)
  add_custom_command(TARGET opensdg_test POST_BUILD
                     COMMAND ${CMAKE_COMMAND} -E copy_if_different
                     ${SODIUM_ROOT}/${CMAKE_VS_PLATFORM_NAME}/Release/v142/dynamic/libsodium.dll
                     $<TARGET_FILE_DIR:opensdg_test>)
endif (MSVC)