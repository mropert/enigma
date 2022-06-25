#include <catch.hpp>

#include "enigma.h"

TEST_CASE("Enigma M4 decodes to itself", "[m4]") {
    enigma::m4_machine machine;
    const std::string message = "All your base";

    REQUIRE(machine.decode(message) == message);
}
