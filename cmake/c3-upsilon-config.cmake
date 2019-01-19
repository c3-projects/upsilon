# This is where it should be
# TODO: actual logic

find_path(c3-upsilon_INCLUDE_DIRS c3/upsilon)
find_library(c3-upsilon_LIBRARIES NAMES c3-upsilon HINTS /usr/lib/c3)
find_package_handle_standard_args(c3-upsilon  DEFAULT_MSG
                                  c3-upsilon_LIBRARIES c3-upsilon_INCLUDE_DIRS)
mark_as_advanced(c3-upsilon_LIBRARIES c3-upsilon_INCLUDE_DIRS)
