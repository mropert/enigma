#pragma once

#include "enigma/m4.h"

#include <array>
#include <functional>
#include <numeric>
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
									 std::array<int, 4> ring_settings,
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

	inline std::size_t unknown_plugboard_match_score( std::string_view plaintext, std::string_view candidate )
	{
		std::array<int, 26> matches = {};

		for ( int i = 0; i < plaintext.size(); ++i )
		{
			if ( plaintext[ i ] == candidate[ i ] )
			{
				++matches[ plaintext[ i ] - 'A' ];
			}
		}
		std::sort( begin( matches ), end( matches ) );
		// With no plugboard only 6 keys can be correct, keep the top matches to avoid false positives
		return std::accumulate( begin( matches ) + 20, end( matches ), 0 );
	}

	inline float index_of_coincidence( std::string_view text )
	{
		std::array<int, 26> distribution = {};

		for ( int i = 0; i < text.size(); ++i )
		{
			++distribution[ text[ i ] - 'A' ];
		}

		int sum = 0;
		for ( int count : distribution )
		{
			sum += count * ( count - 1 );
		}
		return static_cast<float>( sum ) / text.size();
	}
}