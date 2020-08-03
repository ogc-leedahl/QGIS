SET(S4778J_SRCS
        qgsstanag4778jsonprovider.cpp
        qgsstanag4778jsonfeatureiterator.cpp
        ${CMAKE_SOURCE_DIR}/src/providers/common/qgsjwe.cpp
        ${CMAKE_SOURCE_DIR}/src/providers/wfs/qgsbasenetworkrequest.cpp
        ${CMAKE_SOURCE_DIR}/src/providers/wfs/qgswfsconstants.cpp
        )

INCLUDE_DIRECTORIES (
        ${CMAKE_SOURCE_DIR}/src/core
        ${CMAKE_SOURCE_DIR}/src/core/expression
        ${CMAKE_SOURCE_DIR}/src/core/geometry
        ${CMAKE_SOURCE_DIR}/src/core/auth
        ${CMAKE_SOURCE_DIR}/src/core/metadata
        ${CMAKE_SOURCE_DIR}/src/core/symbology
        ${CMAKE_SOURCE_DIR}/src/gui
        ${CMAKE_SOURCE_DIR}/src/gui/auth
        ${CMAKE_SOURCE_DIR}/src/providers/common
        ${CMAKE_SOURCE_DIR}/external
        ${CMAKE_SOURCE_DIR}/external/nlohmann
        ${CMAKE_BINARY_DIR}/src/core
        ${CMAKE_BINARY_DIR}/src/gui
        ${CMAKE_BINARY_DIR}/src/ui
)
INCLUDE_DIRECTORIES(SYSTEM ${QCA_INCLUDE_DIR} ${QTKEYCHAIN_INCLUDE_DIR})

ADD_LIBRARY (stanag4778providers MODULE ${S4778J_SRCS})

TARGET_LINK_LIBRARIES (stanag4778providers
        qgis_core
        ${Qt5Core_LIBRARIES}
        ${Qt5Network_LIBRARIES}
        )

IF (WITH_GUI)
    TARGET_LINK_LIBRARIES (stanag4778providers
            qgis_gui
            )
ENDIF ()

INSTALL(TARGETS stanag4778providers
        RUNTIME DESTINATION ${QGIS_PLUGIN_DIR}
        LIBRARY DESTINATION ${QGIS_PLUGIN_DIR})
