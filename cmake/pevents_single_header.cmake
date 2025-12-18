# Concatenate pevents.h and pevents.cpp into a single header, removing the include line
file(WRITE "${OUTPUT}" "")
foreach(input IN LISTS INPUTS)
    file(READ "${input}" content)
    string(REGEX REPLACE "#include \"pevents.h\"\n" "" content "${content}")
    file(APPEND "${OUTPUT}" "${content}\n")
endforeach()

