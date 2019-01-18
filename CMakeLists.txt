cmake_minimum_required(VERSION 3.9)

project(upsilon)

set(VERSION 0.1.1)

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)
set(CMAKE_CXX_STANDARD 17)

# For some reason, CMAKE_CXX_STANDARD is broken on my system
add_compile_options("-Wall" "-Wextra" "-std=c++17") #"-pedantic"

find_package(PkgConfig REQUIRED)
pkg_search_module(BOTAN REQUIRED botan-2)
include_directories(${BOTAN_INCLUDE_DIRS})

find_package(Threads REQUIRED)

include_directories(${PROJECT_SOURCE_DIR}/include)

file(GLOB_RECURSE source src/*.cpp)

add_library(${PROJECT_NAME} ${source})
#add_executable(${PROJECT_NAME} ${source})

target_link_libraries(${PROJECT_NAME} ${BOTAN_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})

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

SET(CPACK_PACKAGE_VERSION ${VERSION})

install(
  TARGETS ${PROJECT_NAME}
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
  COMPONENT lib
)

install(
  DIRECTORY include/
  DESTINATION include/
  COMPONENT dev
)

if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()

if(NOT DEFINED CPACK_GENERATOR)
  # TODO: platform logic
  set(CPACK_GENERATOR "DEB")
endif()

if(CPACK_GENERATOR STREQUAL "DEB")
  set(CPACK_DEBIAN_PACKAGE_MAINTAINER "c3-projects")
  set(CPACK_DEB_COMPONENT_INSTALL ON)
  set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
  set(CPACK_DEBIAN_ENABLE_COMPONENT_DEPENDS ON)
  set(CPACK_DEBIAN_LIB_PACKAGE_NAME "${PROJECT_NAME}")
  set(CPACK_DEBIAN_DEV_PACKAGE_NAME "${PROJECT_NAME}-dev")
  SET(CPACK_COMPONENT_UNSPECIFIED_HIDDEN "TRUE")
endif()


set(CPACK_COMPONENT_DEV_DEPENDS lib)

INCLUDE(CPack)
