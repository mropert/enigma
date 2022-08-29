#include "enigma/solver.h"

#include <atomic>
#include <execution>
#include <iostream>
#include <numeric>
#include <stdexcept>
#include <thread>

using namespace enigma;

m4_solver::settings m4_solver::brute_force( std::string_view message,
											reflector reflector,
											std::span<const char* const> plugs,
											std::string_view plaintext,
											std::function<void( std::size_t, std::size_t )> progress_update )
{
	std::atomic<std::size_t> progress = 0;
	const std::size_t total = std::size_t( 2 ) * 8 * 7 * 6 * 26 * 26 * 26 * 26 * 26;

	std::array<rotor, 4> wheels = { rotors[ 0 ], rotors[ 0 ], rotors[ 0 ], rotors[ 0 ] };

	const auto root_thread_id = std::this_thread::get_id();
	settings found_settings;

	// Leftmost rotor, beta or gamma
	for ( char left_idx = 9; left_idx <= 10; ++left_idx )
	{
		wheels[ 0 ] = rotors[ left_idx ];

		// Middle left rotor, I to VIII
		for ( char middle_left_index = 1; middle_left_index <= 8; ++middle_left_index )
		{
			wheels[ 1 ] = rotors[ middle_left_index ];
			// Middle right rotor, I to VIII
			for ( char middle_right_index = 1; middle_right_index <= 8; ++middle_right_index )
			{
				if ( middle_right_index == middle_left_index )
				{
					continue;
				}
				wheels[ 2 ] = rotors[ middle_right_index ];

				// Right rotor, I to VIII
				for ( char right_index = 1; right_index <= 8; ++right_index )
				{
					if ( right_index == middle_left_index || right_index == middle_right_index )
					{
						continue;
					}
					wheels[ 3 ] = rotors[ right_index ];

					std::atomic_bool found = false;

					std::array<char, 26> values;
					std::iota( begin( values ), end( values ), 0 );

					std::for_each( std::execution::par_unseq,
								   begin( values ),
								   end( values ),
								   [ & ]( char right_ring_setting )
								   {
#ifdef _DEBUG
									   std::cout << "Trying rotors (" << int( left_idx ) << ", " << int( middle_left_index ) << ", "
												 << int( middle_right_index ) << ", " << int( right_index ) << "), settings (0, 0, "
												 << int( 0 ) << ", " << int( right_ring_setting ) << ")" << std::endl;
#endif


									   const auto key = brute_force_key( message,
																		 wheels,
																		 { 0, 0, 0, right_ring_setting },
																		 reflector,
																		 plugs,
																		 plaintext );
									   if ( !key.empty() )
									   {
										   found = true;
										   found_settings = { { left_idx, middle_left_index, middle_right_index, right_index },
															  { 0, 0, 0, right_ring_setting },
															  key };
									   }

									   if ( found )
									   {
										   return;
									   }

									   progress += std::size_t( 2 ) * 8 * 7 * 6 * 26 * 26;
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
				}
			}
		}
	}

	throw std::logic_error( "Should have matched" );
}


std::string m4_solver::brute_force_key( std::string_view message,
										const std::array<rotor, 4>& rotors,
										std::array<char, 4> ring_settings,
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
					if ( partial_match_score( plaintext, result_buffer ) > plaintext.size() / 4 )
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

	for ( char middle_right_ring = 0; middle_right_ring < 26; ++middle_right_ring )
	{
		key[ 2 ] = ( settings.m_key[ 2 ] - 'A' + middle_right_ring - settings.m_ring_settings[ 2 ] + 26 ) % 26 + 'A';
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

	return {};
}
