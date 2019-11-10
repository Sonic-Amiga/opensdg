cmake_minimum_required(VERSION 3.13)

project(OpenSDG)
option(MSVC_STATIC_BUILD "MSVC_STATIC_BUILD" ON)

include_directories(include)

if (MSVC)
  # Microsoft has their own ideas on C standards, shut them up
  add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
  if (MSVC_STATIC_BUILD)
	# In case we are building static libraries, link also the runtime library statically
	# so that MSVCR*.DLL is not required at runtime.
	# https://msdn.microsoft.com/en-us/library/2kzt1wy3.aspx
	# This is achieved by replacing msvc option /MD with /MT and /MDd with /MTd
	# http://www.cmake.org/Wiki/CMake_FAQ#How_can_I_build_my_MSVC_application_with_a_static_runtime.3F
	foreach(flag_var
		CMAKE_CXX_FLAGS CMAKE_CXX_FLAGS_DEBUG CMAKE_CXX_FLAGS_RELEASE
		CMAKE_CXX_FLAGS_MINSIZEREL CMAKE_CXX_FLAGS_RELWITHDEBINFO)
	  if(${flag_var} MATCHES "/MD")
		string(REGEX REPLACE "/MD" "/MT" ${flag_var} "${${flag_var}}")
	  endif(${flag_var} MATCHES "/MD")
	endforeach(flag_var)
  endif (MSVC_STATIC_BUILD)
endif (MSVC)

add_subdirectory(library)
add_subdirectory(testapp)
