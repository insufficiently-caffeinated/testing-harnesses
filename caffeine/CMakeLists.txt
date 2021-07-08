
add_library(caffeine-dummy SHARED caffeine-dummy.c)
target_link_libraries(caffeine-dummy PRIVATE caffeine::interface)

add_library(caffeine-main STATIC caffeine-main.c)
target_link_libraries(caffeine-main PUBLIC caffeine::interface)
