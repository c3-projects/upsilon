cmake_minimum_required(VERSION 3.9)

set(VERSION 4.0-rc1)

string(REGEX REPLACE "-.*" "" FRIENDLY_VERSION ${VERSION})

project(c3-upsilon VERSION "${FRIENDLY_VERSION}")

#set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)
set(CMAKE_CXX_STANDARD 17)

# Warnings
add_compile_options("-Wall" "-Wextra")
# Security
add_compile_options("-D_FORTIFY_SOURCE=2")
add_compile_options("-fstack-protector-strong")
# Signed o/f protection
add_compile_options("-ftrapv")
# Makes a buch of things r/o
#add_compile_options("-Wl,-z,relro,-z,now")

# Makes a bunch of things r/o so it is harder to exploit
add_link_options("-Wl,-z,relro,-z,now")
find_package(c3-nu REQUIRED)

find_package(PkgConfig REQUIRED)
pkg_search_module(BOTAN REQUIRED botan-2)
include_directories(${BOTAN_INCLUDE_DIRS})

include_directories(include)

file(GLOB_RECURSE source src/*.cpp)

add_library(${PROJECT_NAME} ${source})
#add_executable(${PROJECT_NAME} ${source})

target_link_libraries(${PROJECT_NAME} ${BOTAN_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} c3-nu)
#target_include_directories(${PROJECT_NAME} PUBLIC $<INSTALL_INTERFACE:include/>)

file(GLOB_RECURSE tests tests/*.cxx)

foreach(test ${tests})
  file(RELATIVE_PATH test_rel ${CMAKE_SOURCE_DIR}/tests/ ${test})
  get_filename_component(test_fname ${test_rel} NAME_WE)
  get_filename_component(test_dir ${test_rel} DIRECTORY)
  #string(REGEX REPLACE "/" "_" test_dir ${test_dir})

  set(test_name ${test_dir}_${test_fname})

  add_executable(${test_name} ${test})

  target_link_libraries(${test_name} ${PROJECT_NAME})

  add_test(${test_name} ${test_name})
endforeach()

enable_testing()

SET(CPACK_PACKAGE_VERSION ${PACKAGE_VERSION})

include(GNUInstallDirs)
install(
  TARGETS ${PROJECT_NAME}
  COMPONENT lib
  EXPORT ${PROJECT_NAME}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(
  DIRECTORY include/
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  COMPONENT dev
)

install(
  EXPORT ${PROJECT_NAME}
  FILE ${PROJECT_NAME}-config.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
  COMPONENT dev
)

if(NOT DEFINED CPACK_GENERATOR)
  # TODO: platform logic
  set(CPACK_GENERATOR "DEB")
endif()

if(CPACK_GENERATOR STREQUAL "DEB")
  string(REGEX REPLACE "-" "~" CPACK_DEBIAN_PACKAGE_VERSION ${VERSION})
  set(CPACK_DEBIAN_PACKAGE_MAINTAINER "c3-projects")
  set(CPACK_DEB_COMPONENT_INSTALL ON)
  set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
  set(CPACK_DEBIAN_ENABLE_COMPONENT_DEPENDS ON)
  set(CPACK_DEBIAN_LIB_PACKAGE_NAME "${PROJECT_NAME}")
  set(CPACK_DEBIAN_DEV_PACKAGE_NAME "${PROJECT_NAME}-dev")
  SET(CPACK_COMPONENT_UNSPECIFIED_HIDDEN TRUE)
  string(CONCAT CPACK_DEBIAN_LIB_PACKAGE_DEPENDS
    "botan (>= 2.8.0), botan (<< 3)"
  )
  string(CONCAT CPACK_DEBIAN_DEV_PACKAGE_DEPENDS
    "libstdc++-7-dev | libc++-7-dev,"
    "c3-upsilon (= ${PROJECT_VERSION}),"
    "c3-nu-dev (>= 0.8.0), c3-nu-dev (<< 0.10)"
    )
  message(${CPACK_DEBIAN_DEV_PACKAGE_DEPENDS})
endif()

set(CPACK_COMPONENT_DEV_DEPENDS lib)

INCLUDE(CPack)
