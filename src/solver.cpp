#include "enigma/solver.h"

#include <atomic>
#include <execution>
#include <iostream>
#include <numeric>
#include <stdexcept>
#include <thread>
#include <vector>

using namespace enigma;

std::vector<std::array<int, 4>> generate_rotor_combinations()
{
	std::vector<std::array<int, 4>> combinations;
	combinations.reserve( 2 * 8 * 7 * 6 );

	// Leftmost rotor, beta or gamma
	for ( int left_idx = 9; left_idx <= 10; ++left_idx )
	{
		// Middle left rotor, I to VIII
		for ( int middle_left_index = 1; middle_left_index <= 8; ++middle_left_index )
		{
			// Middle right rotor, I to VIII
			for ( int middle_right_index = 1; middle_right_index <= 8; ++middle_right_index )
			{
				if ( middle_right_index == middle_left_index )
				{
					continue;
				}

				for ( int right_index = 1; right_index <= 8; ++right_index )
				{
					if ( right_index == middle_left_index || right_index == middle_right_index )
					{
						continue;
					}

					combinations.emplace_back( std::array<int, 4> { left_idx, middle_left_index, middle_right_index, right_index } );
				}
			}
		}
	}

	return combinations;
}

m4_solver::settings m4_solver::brute_force( std::string_view message,
											reflector reflector,
											std::span<const char* const> plugs,
											std::string_view plaintext,
											std::function<void( std::size_t, std::size_t )> progress_update )
{
	std::atomic<std::size_t> progress = 0;
	const std::size_t total = std::size_t( 2 ) * 8 * 7 * 6 * 26 * 26 * 26 * 26;

	static const auto rotor_combinations = generate_rotor_combinations();

	const auto root_thread_id = std::this_thread::get_id();
	settings found_settings;
	std::atomic_bool found = false;

	std::for_each( std::execution::par_unseq,
				   begin( rotor_combinations ),
				   end( rotor_combinations ),
				   [ & ]( const std::array<int, 4>& rotor_settings )
				   {
					   const std::array<rotor, 4> wheels = { rotors[ rotor_settings[ 0 ] ],
															 rotors[ rotor_settings[ 1 ] ],
															 rotors[ rotor_settings[ 2 ] ],
															 rotors[ rotor_settings[ 3 ] ] };
					   const auto key = brute_force_key( message, wheels, { 0, 0, 0, 0 }, reflector, plugs, plaintext );
					   if ( !key.empty() )
					   {
						   found = true;
						   found_settings = { rotor_settings, { 0, 0, 0, 0 }, key };
					   }

					   if ( found )
					   {
						   return;
					   }

					   progress += 26 * 26 * 26 * 26;
					   if ( progress_update && root_thread_id == std::this_thread::get_id() )
					   {
						   progress_update( progress, total );
					   }
				   } );

	if ( found )
	{
		const auto final_settings = fine_tune_key( message, found_settings, reflector, plugs, plaintext );
		if ( !final_settings )
		{
			throw std::logic_error( "Fine tune is borked" );
		}
		return *final_settings;
	}

	throw std::logic_error( "Should have matched" );
}


std::string m4_solver::brute_force_key( std::string_view message,
										const std::array<rotor, 4>& rotors,
										std::array<int, 4> ring_settings,
										reflector reflector,
										std::span<const char* const> plugs,
										std::string_view plaintext )
{
	std::string key = "AAAA";
	std::string result_buffer;

	const m4_machine machine( rotors, ring_settings, reflector, plugs );

	for ( int i = 0; i < 26; ++i )
	{
		key[ 0 ] = 'A' + i;
		for ( int j = 0; j < 26; ++j )
		{
			key[ 1 ] = 'A' + j;
			for ( int k = 0; k < 26; ++k )
			{
				key[ 2 ] = 'A' + k;
				for ( int l = 0; l < 26; ++l )
				{
					key[ 3 ] = 'A' + l;
					machine.decode( message, key, result_buffer );
					if ( unknown_plugboard_match_score( plaintext, result_buffer ) >= plaintext.size() / 10 )
					{
						return key;
					}
				}
			}
		}
	}

	return {};
}

std::optional<m4_solver::settings> m4_solver::fine_tune_key( std::string_view message,
															 const settings& settings,
															 reflector reflector,
															 std::span<const char* const> plugs,
															 std::string_view plaintext )
{
	const std::array<rotor, 4> wheels = { rotors[ settings.m_rotors[ 0 ] ],
										  rotors[ settings.m_rotors[ 1 ] ],
										  rotors[ settings.m_rotors[ 2 ] ],
										  rotors[ settings.m_rotors[ 3 ] ] };
	std::string key = settings.m_key;

	for ( int i = 0; i < 26; ++i )
	{
		key[ 2 ] = 'A' + i;
		for ( char middle_right_ring = 0; middle_right_ring < 26; ++middle_right_ring )
		{
			for ( char right_ring = 0; right_ring < 26; ++right_ring )
			{
				key[ 3 ] = ( settings.m_key[ 3 ] - 'A' + right_ring - settings.m_ring_settings[ 3 ] + 26 ) % 26 + 'A';
				const m4_machine machine( wheels, { 0, 0, middle_right_ring, right_ring }, reflector, plugs );
				if ( machine.decode( message, key ) == plaintext )
				{
					auto final_settings = settings;
					final_settings.m_ring_settings[ 2 ] = middle_right_ring;
					final_settings.m_ring_settings[ 3 ] = right_ring;
					final_settings.m_key = key;
					return final_settings;
				}
			}
		}
	}

	return {};
}
