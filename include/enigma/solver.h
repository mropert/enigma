#pragma once

#include "enigma/m4.h"

#include <array>
#include <functional>
#include <optional>
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

		std::optional<settings> fine_tune_key( std::string_view message,
											   const settings& settings,
											   reflector reflector,
											   std::span<const char* const> plugs,
											   std::string_view plaintext );

		settings brute_force( std::string_view message,
							  reflector reflector,
							  std::span<const char* const> plugs,
							  std::string_view plaintext,
							  std::function<void( std::size_t, std::size_t )> progress_update = {} );
	}

	inline std::size_t partial_match_score( std::string_view plaintext, std::string_view candidate )
	{
		std::size_t matches = 0;
		std::size_t score = 0;

		for ( int i = 0; i < plaintext.size(); ++i )
		{
			if ( plaintext[ i ] == candidate[ i ] )
			{
				++matches;
				if ( matches > score )
				{
					score = matches;
				}
			}
			else
			{
				matches = 0;
			}
		}

		return score;
	}
}