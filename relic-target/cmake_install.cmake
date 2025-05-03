# Install script for directory: /Users/gustavnielsen/Documents/Kode.nosync/relic-0.7.0

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

# Set path to fallback-tool for dependency-resolution.
if(NOT DEFINED CMAKE_OBJDUMP)
  set(CMAKE_OBJDUMP "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/objdump")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/relic" TYPE FILE FILES
    "/Users/gustavnielsen/Documents/Kode.nosync/relic-0.7.0/include/relic.h"
    "/Users/gustavnielsen/Documents/Kode.nosync/relic-0.7.0/include/relic_alloc.h"
    "/Users/gustavnielsen/Documents/Kode.nosync/relic-0.7.0/include/relic_arch.h"
    "/Users/gustavnielsen/Documents/Kode.nosync/relic-0.7.0/include/relic_bc.h"
    "/Users/gustavnielsen/Documents/Kode.nosync/relic-0.7.0/include/relic_bench.h"
    "/Users/gustavnielsen/Documents/Kode.nosync/relic-0.7.0/include/relic_bn.h"
    "/Users/gustavnielsen/Documents/Kode.nosync/relic-0.7.0/include/relic_core.h"
    "/Users/gustavnielsen/Documents/Kode.nosync/relic-0.7.0/include/relic_cp.h"
    "/Users/gustavnielsen/Documents/Kode.nosync/relic-0.7.0/include/relic_dv.h"
    "/Users/gustavnielsen/Documents/Kode.nosync/relic-0.7.0/include/relic_eb.h"
    "/Users/gustavnielsen/Documents/Kode.nosync/relic-0.7.0/include/relic_ec.h"
    "/Users/gustavnielsen/Documents/Kode.nosync/relic-0.7.0/include/relic_ed.h"
    "/Users/gustavnielsen/Documents/Kode.nosync/relic-0.7.0/include/relic_ep.h"
    "/Users/gustavnielsen/Documents/Kode.nosync/relic-0.7.0/include/relic_epx.h"
    "/Users/gustavnielsen/Documents/Kode.nosync/relic-0.7.0/include/relic_err.h"
    "/Users/gustavnielsen/Documents/Kode.nosync/relic-0.7.0/include/relic_fb.h"
    "/Users/gustavnielsen/Documents/Kode.nosync/relic-0.7.0/include/relic_fbx.h"
    "/Users/gustavnielsen/Documents/Kode.nosync/relic-0.7.0/include/relic_fp.h"
    "/Users/gustavnielsen/Documents/Kode.nosync/relic-0.7.0/include/relic_fpx.h"
    "/Users/gustavnielsen/Documents/Kode.nosync/relic-0.7.0/include/relic_label.h"
    "/Users/gustavnielsen/Documents/Kode.nosync/relic-0.7.0/include/relic_md.h"
    "/Users/gustavnielsen/Documents/Kode.nosync/relic-0.7.0/include/relic_mpc.h"
    "/Users/gustavnielsen/Documents/Kode.nosync/relic-0.7.0/include/relic_multi.h"
    "/Users/gustavnielsen/Documents/Kode.nosync/relic-0.7.0/include/relic_pc.h"
    "/Users/gustavnielsen/Documents/Kode.nosync/relic-0.7.0/include/relic_pp.h"
    "/Users/gustavnielsen/Documents/Kode.nosync/relic-0.7.0/include/relic_rand.h"
    "/Users/gustavnielsen/Documents/Kode.nosync/relic-0.7.0/include/relic_test.h"
    "/Users/gustavnielsen/Documents/Kode.nosync/relic-0.7.0/include/relic_types.h"
    "/Users/gustavnielsen/Documents/Kode.nosync/relic-0.7.0/include/relic_util.h"
    )
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/relic/low" TYPE FILE FILES
    "/Users/gustavnielsen/Documents/Kode.nosync/relic-0.7.0/include/low/relic_bn_low.h"
    "/Users/gustavnielsen/Documents/Kode.nosync/relic-0.7.0/include/low/relic_dv_low.h"
    "/Users/gustavnielsen/Documents/Kode.nosync/relic-0.7.0/include/low/relic_fb_low.h"
    "/Users/gustavnielsen/Documents/Kode.nosync/relic-0.7.0/include/low/relic_fp_low.h"
    "/Users/gustavnielsen/Documents/Kode.nosync/relic-0.7.0/include/low/relic_fpx_low.h"
    )
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/relic" TYPE DIRECTORY FILES "/Users/gustavnielsen/Documents/Kode.nosync/relic-target/include/")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/cmake" TYPE FILE FILES "/Users/gustavnielsen/Documents/Kode.nosync/relic-0.7.0/cmake/relic-config.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for each subdirectory.
  include("/Users/gustavnielsen/Documents/Kode.nosync/relic-target/src/cmake_install.cmake")
  include("/Users/gustavnielsen/Documents/Kode.nosync/relic-target/test/cmake_install.cmake")
  include("/Users/gustavnielsen/Documents/Kode.nosync/relic-target/bench/cmake_install.cmake")

endif()

if(CMAKE_INSTALL_COMPONENT)
  if(CMAKE_INSTALL_COMPONENT MATCHES "^[a-zA-Z0-9_.+-]+$")
    set(CMAKE_INSTALL_MANIFEST "install_manifest_${CMAKE_INSTALL_COMPONENT}.txt")
  else()
    string(MD5 CMAKE_INST_COMP_HASH "${CMAKE_INSTALL_COMPONENT}")
    set(CMAKE_INSTALL_MANIFEST "install_manifest_${CMAKE_INST_COMP_HASH}.txt")
    unset(CMAKE_INST_COMP_HASH)
  endif()
else()
  set(CMAKE_INSTALL_MANIFEST "install_manifest.txt")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  string(REPLACE ";" "\n" CMAKE_INSTALL_MANIFEST_CONTENT
       "${CMAKE_INSTALL_MANIFEST_FILES}")
  file(WRITE "/Users/gustavnielsen/Documents/Kode.nosync/relic-target/${CMAKE_INSTALL_MANIFEST}"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
endif()
