set(TESTAPP_SOURCES devismart.c devismart.h devismart_config.c devismart_protocol.h
                    jsmn.h main.c testapp.h)

add_executable(opensdg_test ${TESTAPP_SOURCES} ${PUBLIC_INCLUDE_FILES})
target_link_libraries(opensdg_test PUBLIC opensdg)

if (MSVC AND STATIC_BUILD)
  # Unfortunately we don't have .pdb for static libsodium'
  target_link_options(opensdg_test PRIVATE "/ignore:4099")
endif (MSVC AND STATIC_BUILD)

if (MSVC AND (NOT STATIC_BUILD))
  # Copy DLLs in order to be able to run the test app from its build directory
  add_custom_target(copyDLL ${CMAKE_COMMAND} -E copy_if_different
                                             $<TARGET_FILE_DIR:opensdg>/opensdg.dll
                                             ${CMAKE_CURRENT_BINARY_DIR}/$(Configuration)
                    COMMAND ${CMAKE_COMMAND} -E copy_if_different
                                             ${SODIUM_ROOT}/${CMAKE_VS_PLATFORM_NAME}/Release/v142/dynamic/libsodium.dll
                                             ${CMAKE_CURRENT_BINARY_DIR}/$(Configuration))
  add_dependencies(opensdg_test copyDLL)
endif (MSVC AND (NOT STATIC_BUILD))
