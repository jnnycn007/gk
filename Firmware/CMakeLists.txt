cmake_minimum_required(VERSION 3.11 FATAL_ERROR)

if(NOT CMAKE_BUILD_TYPE)
    message(STATUS "CMAKE_BUILD_TYPE not set, defaulting to DEBUG")
    set(CMAKE_BUILD_TYPE DEBUG)
else()
    message(STATUS "CMAKE_BUILD_TYPE: ${CMAKE_BUILD_TYPE}")
endif()

message(STATUS "CMAKE_TOOLCHAIN_FILE: ${CMAKE_TOOLCHAIN_FILE}")

include(cmake/utils.cmake)

add_definitions(-DCONFIG_BLOCK_DEV_CACHE_SIZE=32)
add_definitions(-DCONFIG_HAVE_OWN_OFLAGS=0)
add_subdirectory(lwext4 lwext4)
set(LWEXT4_GENERATED_DIR "${CMAKE_CURRENT_BINARY_DIR}/lwext4/include")

set(ZLIB_BUILD_EXAMPLES OFF)
add_subdirectory(zlib-1.3.1 zlib)

project(gkv3 C CXX ASM)

file(GLOB_RECURSE SOURCES CONFIGURE_DEPENDS
    ${CMAKE_CURRENT_SOURCE_DIR}/src/*.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/*.s
    ${CMAKE_CURRENT_SOURCE_DIR}/fatfs/source/ff.c
    ${CMAKE_CURRENT_SOURCE_DIR}/fatfs/source/ffsystem.c
    ${CMAKE_CURRENT_SOURCE_DIR}/fatfs/source/ffunicode.c
)

file(GLOB_RECURSE TUSB_SOURCES CONFIGURE_DEPENDS
    ${CMAKE_CURRENT_SOURCE_DIR}/tinyusb/src/*.c
    ${CMAKE_CURRENT_SOURCE_DIR}/tinyusb/lib/networking/rndis_reports.c
)

file(GLOB_RECURSE WINC_SOURCES CONFIGURE_DEPENDS
    ${CMAKE_CURRENT_SOURCE_DIR}/wilc/common/source/*.c
    ${CMAKE_CURRENT_SOURCE_DIR}/wilc/driver/source/*.c
)

add_library(tusb)
target_include_directories(tusb
    PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/inc"
        "${CMAKE_CURRENT_SOURCE_DIR}/cmsis_device_h7rs/Include"
        "${CMAKE_CURRENT_SOURCE_DIR}/cmsis_Core/Include"
        "${CMAKE_CURRENT_SOURCE_DIR}/gk-userlandinterface"
        "${CMAKE_CURRENT_SOURCE_DIR}/tinyusb/src"
        "${CMAKE_CURRENT_SOURCE_DIR}/tinyusb/lib/networking"
)
target_compile_definitions(tusb
    PRIVATE
        STM32H7S7xx
        CORE_CM7
        ETH_MODE
        _POSIX_READER_WRITER_LOCKS
        _UNIX98_THREAD_MUTEX_ATTRIBUTES
        _POSIX_THREAD_PRIO_PROTECT
        _POSIX_THREAD_PROCESS_SHARED

)

target_sources(tusb
    PRIVATE
        ${TUSB_SOURCES}
)


add_library(wilc)
target_include_directories(wilc
    PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/inc"
        "${CMAKE_CURRENT_SOURCE_DIR}/cmsis_device_h7rs/Include"
        "${CMAKE_CURRENT_SOURCE_DIR}/cmsis_Core/Include"
        "${CMAKE_CURRENT_SOURCE_DIR}/gk-userlandinterface"
        "${CMAKE_CURRENT_SOURCE_DIR}/wilc"
)
target_compile_definitions(wilc
    PRIVATE
    STM32H7S7xx
    CORE_CM7
    ETH_MODE
    _POSIX_READER_WRITER_LOCKS
    _UNIX98_THREAD_MUTEX_ATTRIBUTES
    _POSIX_THREAD_PRIO_PROTECT
    _POSIX_THREAD_PROCESS_SHARED
    CONF_WILC_USE_SPI
    CONF_WILC_USE_3000_REV_A
    NM_EDGE_INTERRUPT=1

)

target_sources(wilc
    PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/wilc/common/source/nm_common.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/wilc/driver/source/m2m_hif.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/wilc/driver/source/m2m_periph.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/wilc/driver/source/m2m_wifi.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/wilc/driver/source/nmasic.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/wilc/driver/source/nmbus.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/wilc/driver/source/nmdrv.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/wilc/driver/source/nmi2c.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/wilc/driver/source/nmsdio.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/wilc/driver/source/nmspi.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/wilc/driver/source/spi_flash.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/wilc/drv_hash/PMK.c"
)


add_executable(${PROJECT_NAME})


target_include_directories(${PROJECT_NAME}
    PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/inc"
        "${CMAKE_CURRENT_SOURCE_DIR}/cmsis_device_h7rs/Include"
        "${CMAKE_CURRENT_SOURCE_DIR}/cmsis_core/Include"
        "${CMAKE_CURRENT_SOURCE_DIR}/gk-userlandinterface"
        "${CMAKE_CURRENT_SOURCE_DIR}/lwext4/include"
        "${LWEXT4_GENERATED_DIR}"
        "${CMAKE_CURRENT_SOURCE_DIR}/tinyusb/src"
        "${CMAKE_CURRENT_SOURCE_DIR}/winc1500"
        "${CMAKE_CURRENT_SOURCE_DIR}/fatfs/source"
        "${CMAKE_CURRENT_SOURCE_DIR}/nemagfx/inc"
        "${CMAKE_CURRENT_SOURCE_DIR}/wilc"
        "${CMAKE_CURRENT_SOURCE_DIR}/inih"
        "${CMAKE_CURRENT_SOURCE_DIR}/src"
)

target_compile_definitions(${PROJECT_NAME}
    PRIVATE
        STM32H7S7xx
        CORE_CM7
        ETH_MODE
        _POSIX_READER_WRITER_LOCKS
        _UNIX98_THREAD_MUTEX_ATTRIBUTES
        _POSIX_THREAD_PRIO_PROTECT
        _POSIX_THREAD_PROCESS_SHARED

)

target_sources(${PROJECT_NAME}
    PRIVATE
        ${SOURCES}
)


set_target_properties(${PROJECT_NAME}
    PROPERTIES
        SUFFIX ".elf"
        C_STANDARD 11
        C_EXTENSIONS ON
        CMAKE_C_STANDARD_REQUIRED ON
        CXX_STANDARD 17
        CXX_EXTENSIONS ON
        CMAKE_CXX_STANDARD_REQUIRED ON
)

target_compile_options(${PROJECT_NAME}
    PRIVATE
        -Wall
        -Wextra
        -Werror
        -Wduplicated-cond
        -Wno-duplicated-branches
        -Wlogical-op
        -Wnull-dereference
        -Wshadow
        -Wno-unused-parameter
        -Wno-psabi
        -Wno-missing-field-initializers
)

target_compile_options(${PROJECT_NAME}
    PRIVATE
        $<$<COMPILE_LANGUAGE:C>:
            -Wstrict-prototypes
            -Wno-missing-prototypes
            -Wno-address
        >)

target_compile_options(${PROJECT_NAME}
    PRIVATE
        $<$<COMPILE_LANGUAGE:CXX>:
            -Wno-register
        >)

target_link_libraries(${PROJECT_NAME}
    PRIVATE
        -lm
        lwext4
        tusb
        wilc
        zlib
        #lvgl
        ${CMAKE_CURRENT_SOURCE_DIR}/nemagfx/lib/libnemagfx-float-abi-hard.a

)

target_link_options(${PROJECT_NAME}
    PRIVATE
        -Wl,-Map=${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}.map,--cref


#        -Wl,--wrap,malloc
#        -Wl,--wrap,_malloc_r
#        -Wl,--wrap,calloc
#        -Wl,--wrap,_calloc_r
#        -Wl,--wrap,realloc
#        -Wl,--wrap,_realloc_r
#        -Wl,--wrap,free
#        -Wl,--wrap,_free_r
)

utils_target_set_linker_script(${PROJECT_NAME}
    ${CMAKE_CURRENT_SOURCE_DIR}/stm32h7s7xx_flash.ld
)

utils_target_print_size(${PROJECT_NAME})

add_subdirectory(xspi_flasher)
