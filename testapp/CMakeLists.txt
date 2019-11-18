set(TESTAPP_SOURCES devismart.c devismart.h devismart_protocol.h
                    main.c testapp.h)

add_executable(opensdg_test ${TESTAPP_SOURCES} ${PUBLIC_INCLUDE_FILES})
target_link_libraries(opensdg_test PUBLIC opensdg)

if (MSVC)
  # Copy DLLs in order to be able to run the test app from its build directory
  add_custom_target(copyDLL ${CMAKE_COMMAND} -E copy_if_different
                                             $<TARGET_FILE_DIR:opensdg>/opensdg.dll
                                             ${CMAKE_CURRENT_BINARY_DIR}/$(Configuration)
                    COMMAND ${CMAKE_COMMAND} -E copy_if_different
                                             ${SODIUM_ROOT}/${CMAKE_VS_PLATFORM_NAME}/Release/v142/dynamic/libsodium.dll
                                             ${CMAKE_CURRENT_BINARY_DIR}/$(Configuration))
  add_dependencies(opensdg_test copyDLL)
endif (MSVC)
