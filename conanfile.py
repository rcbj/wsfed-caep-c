# The recipe for building this library from a checkout, so a clone of a release tag
# goes into the local Conan cache:
#
#   conan create . --build=missing
#
# It builds from the files in this tree, never from a download. conan/ holds the
# ConanCenter-layout recipe, which builds from the GitHub release archive instead;
# both run conan/all/test_package/.
import os

from conan import ConanFile
from conan.errors import ConanException, ConanInvalidConfiguration
from conan.tools.build import check_min_cppstd, stdcpp_library
from conan.tools.cmake import CMake, CMakeDeps, CMakeToolchain, cmake_layout
from conan.tools.files import copy, load, rmdir

required_conan_version = ">=2.1"


class IyaWsfedCaepConan(ConanFile):
    name = "iya-wsfed-caep"
    description = "Server-side WS-Federation relying party for C and C++, with a CAEP and RISC Shared Signals receiver"
    license = "MIT"
    url = "https://github.com/rcbj/wsfed-caep-c"
    homepage = "https://github.com/rcbj/wsfed-caep-c"
    topics = ('ws-federation', 'wsfed', 'saml', 'caep', 'risc', 'shared-signals')
    package_type = "library"
    settings = "os", "arch", "compiler", "build_type"
    options = {
        "shared": [True, False],
        "fPIC": [True, False],
    }
    default_options = {
        "shared": False,
        "fPIC": True,
    }
    implements = ["auto_shared_fpic"]
    exports_sources = "CMakeLists.txt", "VERSION", "LICENSE", "cmake/*", "include/*", "src/*"
    test_package_folder = "conan/all/test_package"

    def set_version(self):
        # VERSION is the one version: the CMake project, the release tag and this package.
        self.version = load(self, os.path.join(self.recipe_folder, "VERSION")).strip()

    def export(self):
        # A --version that is not VERSION's would label this tree as another release.
        version = load(self, os.path.join(self.recipe_folder, "VERSION")).strip()
        if str(self.version) != version:
            raise ConanException(
                f"--version {self.version} is not this checkout's VERSION, {version}")

    def layout(self):
        cmake_layout(self)

    def requirements(self):
        self.requires("openssl/[>=3 <4]")
        self.requires("libxml2/[>=2.12 <3]")

    def validate(self):
        check_min_cppstd(self, 17)
        # POSIX sockets and threads; the library has not been ported to Windows.
        if self.settings.os == "Windows":
            raise ConanInvalidConfiguration(f"{self.ref} does not support Windows yet")

    def build_requirements(self):
        self.tool_requires("cmake/[>=3.16 <4]")

    def generate(self):
        tc = CMakeToolchain(self)
        tc.cache_variables["IYA_WSFED_BUILD_TESTS"] = False
        tc.cache_variables["IYA_WSFED_BUILD_PROGRAMS"] = False
        tc.generate()
        CMakeDeps(self).generate()

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def package(self):
        copy(self, "LICENSE", self.source_folder, os.path.join(self.package_folder, "licenses"))
        cmake = CMake(self)
        cmake.install()
        rmdir(self, os.path.join(self.package_folder, "lib", "cmake"))

    def package_info(self):
        self.cpp_info.set_property("cmake_file_name", "iya_wsfed")
        self.cpp_info.set_property("cmake_target_name", "iya::wsfed")
        self.cpp_info.libs = ["iya_wsfed"]
        if self.settings.os in ["Linux", "FreeBSD"]:
            self.cpp_info.system_libs.append("pthread")
        if not self.options.shared:
            libcxx = stdcpp_library(self)
            if libcxx:
                self.cpp_info.system_libs.append(libcxx)
