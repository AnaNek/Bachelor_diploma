cmake_minimum_required(VERSION 3.0)

project(fhe_redis VERSION 0.1.0 DESCRIPTION "fully homomorphic encryption for redis")

set(CMAKE_CXX_STANDARD 17)

set(MODULE_SRCS fhe_redis.cpp serializers.cpp)

set(CMAKE_BUILD_TYPE RelWithDebInfo)

add_library(fhe_redis MODULE ${MODULE_SRCS})
set_target_properties(fhe_redis PROPERTIES PREFIX "")
target_link_libraries(fhe_redis helib)

find_package(helib REQUIRED)

if (helib-NOTFOUND)
	message(WARNING "helib not found")
endif()

install(TARGETS fhe_redis DESTINATION lib PERMISSIONS WORLD_EXECUTE)