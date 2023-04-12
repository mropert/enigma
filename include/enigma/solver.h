#pragma once

#include "enigma/m4.h"

#include <array>
#include <functional>
#include <numeric>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

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

		std::vector<std::string> brute_force_key( std::string_view message,
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

		std::optional<settings> brute_force( std::string_view message,
											 reflector reflector,
											 std::span<const char* const> plugs,
											 std::string_view plaintext,
											 std::function<void( std::size_t, std::size_t, std::size_t )> progress_update = {} );
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
			}
			else
			{
				score += matches * matches;
				matches = 0;
			}
		}

		score += matches * matches;

		return score;
	}

	inline std::size_t partial_match_reference_score( std::size_t message_length )
	{
		// Pure random would get roughly 1 in 26 letters correct
		// (Give or take since natural language doesn't use all letters with same frequency)
		// Testing gave between 0.04 and 0.05 score per letter in the message for wrong settings
		return message_length * 0.05 * 5;
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
		return static_cast<float>( sum ) * 26 / ( text.size() * ( text.size() - 1 ) );
	}

	std::vector<int> find_potential_crib_location( std::string_view cyphertext, std::string_view crib );
}