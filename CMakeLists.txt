cmake_minimum_required(VERSION 3.16)

# The version is VERSION's, so the library, the package and the release tag agree.
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" IYA_WSFED_VERSION)
string(STRIP "${IYA_WSFED_VERSION}" IYA_WSFED_VERSION)
project(wsfed-caep-c VERSION ${IYA_WSFED_VERSION} LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)
set(CMAKE_CXX_EXTENSIONS ON)

# On when this is the top-level project (a checkout, the Docker test stage); a package
# build (a Conan recipe, add_subdirectory) turns them off and gets the library alone.
if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
  set(IYA_WSFED_TOP_LEVEL ON)
else()
  set(IYA_WSFED_TOP_LEVEL OFF)
endif()
option(IYA_WSFED_BUILD_TESTS "Build the tests" ${IYA_WSFED_TOP_LEVEL})
option(IYA_WSFED_BUILD_PROGRAMS "Build the demo and the command-line programs" ${IYA_WSFED_TOP_LEVEL})

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)
find_package(LibXml2 REQUIRED)

# Static or shared as BUILD_SHARED_LIBS says (static when it is unset).
add_library(iya_wsfed
  src/crypto.cpp
  src/util.cpp
  src/http.cpp
  src/config.cpp
  src/metadata.cpp
  src/signature.cpp
  src/encryption.cpp
  src/token.cpp
  src/party.cpp
  src/ssf.cpp
  src/cli.cpp
  src/c_api.cpp)
add_library(iya::wsfed ALIAS iya_wsfed)
target_include_directories(iya_wsfed
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
         $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(iya_wsfed PUBLIC OpenSSL::SSL OpenSSL::Crypto Threads::Threads LibXml2::LibXml2)
# The C++ headers need C++17; a consumer gets that from the target.
target_compile_features(iya_wsfed PUBLIC cxx_std_17)
set_target_properties(iya_wsfed PROPERTIES
  EXPORT_NAME wsfed
  POSITION_INDEPENDENT_CODE ON
  VERSION ${PROJECT_VERSION}
  # 0.x: every minor version may break the ABI.
  SOVERSION ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR})

# The library, its public headers (include/ holds nothing else), and a CMake package:
#   find_package(iya_wsfed REQUIRED)
#   target_link_libraries(app PRIVATE iya::wsfed)
install(TARGETS iya_wsfed EXPORT iya_wsfedTargets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT iya_wsfedTargets NAMESPACE iya:: DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/iya_wsfed)
configure_package_config_file(cmake/iya_wsfedConfig.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/iya_wsfedConfig.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/iya_wsfed)
write_basic_package_version_file(${CMAKE_CURRENT_BINARY_DIR}/iya_wsfedConfigVersion.cmake
  COMPATIBILITY SameMinorVersion)
install(FILES
  ${CMAKE_CURRENT_BINARY_DIR}/iya_wsfedConfig.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/iya_wsfedConfigVersion.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/iya_wsfed)

if(IYA_WSFED_BUILD_PROGRAMS OR IYA_WSFED_BUILD_TESTS)
# The demo web app, for wsfed-demo and the tests: never installed, never in the library.
add_library(iya_wsfed_demo STATIC src/demo.cpp src/demo_c_api.cpp)
target_include_directories(iya_wsfed_demo PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(iya_wsfed_demo PUBLIC iya_wsfed)
add_executable(wsfed-caep src/cli_main.cpp)
target_link_libraries(wsfed-caep PRIVATE iya_wsfed)
add_executable(wsfed-demo src/demo_main.cpp)
target_link_libraries(wsfed-demo PRIVATE iya_wsfed_demo)
install(TARGETS wsfed-caep wsfed-demo RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(IYA_WSFED_BUILD_TESTS)
add_executable(wsfed_tests tests/harness.c tests/suite.c tests/cases.c tests/trust.c)
target_link_libraries(wsfed_tests PRIVATE iya_wsfed_demo iya_wsfed OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
target_include_directories(wsfed_tests PRIVATE include)
add_executable(wsfed_cpp_smoke tests/cpp_smoke.cpp)
target_link_libraries(wsfed_cpp_smoke PRIVATE iya_wsfed)
target_include_directories(wsfed_cpp_smoke PRIVATE include)
enable_testing()
set(WSFED_CASES
  TestConfigurationRequiresRealmReplyAndAMatchingKey
  TestSignalsOmittedOrTrueIsLeftOff
  TestSignalsFalseIsRecorded
  TestSignalsMustBeTrueOrFalse
  TestReadsTheSecurityTokenServiceRole
  TestXsiTypeAndIdpRoleFallback
  TestRefusesMetadataWithoutAnSTSOrSAML2
  TestWritesApplicationServiceMetadata
  TestSigninNamesRealmReplyWctxAndSAML2
  TestForceAuthnAndProtocolParams
  TestSignoutRequest
  TestSignedAssertionInA2005Response
  TestTrust13AndARawFormBody
  TestRecipientOptionalAndChecked
  TestBareBearerConfirmation
  TestUnsignedAssertionIsRefused
  TestAlteredOrWrongKeyIsRefused
  TestSignatureWrapping
  TestWrongRealmIssuerOrExpiry
  TestInResponseToIsRefused
  TestSaml11AndNonTrustAreRefused
  TestUnsolicitedAndUnknownRequests
  TestReplay
  TestDecryptsEncryptedAssertions
  TestWantAssertionsEncryptedAndTamperedCiphertext
  TestEncryptedAttributeAndMissingKey
  TestReplyURLRefusesGetWrongWaAndWresultptr
  TestSignOutCleanup
  TestStatusSuccessConstant
  TestVerifiesASetAndRefusesTheWrongKey
  TestSubjects
  TestPollStreamEndsTheNamedSessions
  TestForgedSetsAreReported
  TestEventCatalog
  TestHandlerAndOnEndErrorsAreStillAcknowledged
  TestOverlappingPollsHandleASetOnce
  TestRefusesATransmitterWithoutPollDelivery
  TestConfigureSignalsBehavior
  TestSignsItselfAndNamesItsKey
  TestTwoCertificatesOfOneNameHaveDifferentKeyIdentifiers
  TestGenerateKeysNamesTheCertificateAfterTheRealm
  TestSignInCleanupAndLogout
  TestLiveStatusReportsTheSignInWithoutTokens
  TestIdpCaChainIsTheTrustStore
  TestHostNameIsChecked
  TestConfigureWritesTheWholeChain
)
foreach(case ${WSFED_CASES})
  add_test(NAME ${case} COMMAND wsfed_tests ${case})
  set_tests_properties(${case} PROPERTIES WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
endforeach()
add_test(NAME CppSmoke COMMAND wsfed_cpp_smoke)
set_tests_properties(CppSmoke PROPERTIES WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
endif()
