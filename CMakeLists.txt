cmake_minimum_required(VERSION 3.16)
project(wsfed-caep-c VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)
set(CMAKE_CXX_EXTENSIONS ON)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBXML2 REQUIRED libxml-2.0)

add_library(wsfed STATIC
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
  src/demo.cpp
  src/c_api.cpp
)
target_include_directories(wsfed PUBLIC include ${LIBXML2_INCLUDE_DIRS} PRIVATE src)
target_link_libraries(wsfed PUBLIC OpenSSL::SSL OpenSSL::Crypto Threads::Threads ${LIBXML2_LIBRARIES})

add_executable(wsfed-caep src/cli_main.cpp)
target_link_libraries(wsfed-caep PRIVATE wsfed)

add_executable(wsfed-demo src/demo_main.cpp)
target_link_libraries(wsfed-demo PRIVATE wsfed)

add_executable(wsfed_tests tests/harness.c tests/suite.c tests/cases.c tests/trust.c)
target_link_libraries(wsfed_tests PRIVATE wsfed OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
target_include_directories(wsfed_tests PRIVATE include)

add_executable(wsfed_cpp_smoke tests/cpp_smoke.cpp)
target_link_libraries(wsfed_cpp_smoke PRIVATE wsfed)
target_include_directories(wsfed_cpp_smoke PRIVATE include)

include(GNUInstallDirs)
install(TARGETS wsfed-caep wsfed-demo RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

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
