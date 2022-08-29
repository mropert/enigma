#pragma once

#include "enigma/m4.h"

#include <array>
#include <functional>
#include <string>
#include <string_view>

namespace enigma
{
	namespace m4_solver
	{
		struct settings
		{
			std::array<int, 4> m_rotors;
			std::array<int, 4> m_ring_settings;
			std::string m_key;
		};

		std::string brute_force_key( std::string_view message,
									 const std::array<rotor, 4>& rotors,
									 std::array<char, 4> ring_settings,
									 reflector reflector,
									 std::span<const char* const> plugs,
									 std::string_view plaintext );

		settings brute_force( std::string_view message,
							  reflector reflector,
							  std::span<const char* const> plugs,
							  std::string_view plaintext,
							  std::function<void( std::size_t, std::size_t )> progress_update = {} );
	}

}